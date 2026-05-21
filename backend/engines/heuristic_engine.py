"""
PhishSentinel — engines/heuristic_engine.py
Heuristic analysis engine.

Checks:
  1. Homograph / IDN Spoofing   → Unicode lookalike chars in domain
  2. Typosquatting              → Levenshtein distance ≤ 2 from known brands
  3. URL Shortener Expansion    → follow redirects to reveal real destination
  4. Redirect Chain Analysis    → count hops; many hops = evasion
  5. Keyword Injection          → brand name in subdomain/path but different root
                                  e.g. paypal-secure-login.evil.xyz
"""

import asyncio
import logging
import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx

from config import (
    HOMOGRAPH_MAP, TOP_BRANDS, URL_SHORTENERS, TYPOSQUAT_EDIT_DISTANCE,
)

log = logging.getLogger("PhishSentinel.Heuristic")
_executor = ThreadPoolExecutor(max_workers=5)


# ── Levenshtein Distance ──────────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j]     + 1,         # deletion
                curr[j - 1] + 1,         # insertion
                prev[j - 1] + (ca != cb) # substitution
            ))
        prev = curr
    return prev[-1]


# ── Homograph Detection ───────────────────────────────────────────────────────

def normalise_homograph(domain: str) -> str:
    """
    Decode punycode (xn--...) then map confusable Unicode chars to their
    ASCII equivalents so the domain can be compared against known brands.
    """
    # Decode IDN labels
    try:
        decoded = domain.encode("ascii").decode("idna") if "xn--" in domain else domain
    except (UnicodeError, UnicodeDecodeError):
        decoded = domain

    # NFKD normalise (ﬁ → fi, etc.)
    decoded = unicodedata.normalize("NFKD", decoded)

    # Map confusable chars
    result = ""
    for ch in decoded:
        result += HOMOGRAPH_MAP.get(ch, ch)
    return result.lower()


def check_homograph(domain: str) -> dict:
    """
    Returns a finding if the domain uses Unicode lookalike characters
    that make it appear to be a known brand.
    """
    findings = []
    score    = 0

    # Check for xn-- punycode in any label
    labels = domain.split(".")
    has_punycode = any(l.startswith("xn--") for l in labels)
    has_non_ascii = any(ord(c) > 127 for c in domain)

    if not has_punycode and not has_non_ascii:
        return {"score": 0, "findings": [], "matched_brand": None}

    normalised = normalise_homograph(domain)
    # Strip TLD for brand comparison
    normalised_base = normalised.rsplit(".", 1)[0].replace("-", "").replace(".", "")

    for brand in TOP_BRANDS:
        if normalised_base == brand or normalised_base.startswith(brand) or normalised_base.endswith(brand):
            score = 95
            findings.append(
                f"IDN homograph attack: '{domain}' uses Unicode lookalike characters "
                f"to impersonate '{brand}'. Normalised form: '{normalised}'."
            )
            return {"score": score, "findings": findings, "matched_brand": brand}

    if has_punycode or has_non_ascii:
        score = 40
        findings.append(
            f"Domain '{domain}' contains non-ASCII or punycode characters. "
            "While not always malicious, this is a common IDN spoofing vector."
        )

    return {"score": score, "findings": findings, "matched_brand": None}


# ── Typosquatting Detection ───────────────────────────────────────────────────

def check_typosquat(domain: str) -> dict:
    """
    Compare the registered domain (TLD+1) against known brand names.
    Uses Levenshtein distance — close but not equal = typosquat.
    Also detects keyword injection (brand in subdomain, different root).
    """
    findings = []
    score    = 0
    matched  = None

    parts = domain.lower().split(".")
    # Registered domain = last two labels (name + TLD)
    registered = parts[-2] if len(parts) >= 2 else parts[0]
    full_no_tld = ".".join(parts[:-1])   # everything except TLD

    for brand in TOP_BRANDS:
        brand_clean = brand.replace("-", "").replace(".", "")
        reg_clean   = registered.replace("-", "")

        # Exact match = legitimate (not a typosquat)
        if reg_clean == brand_clean:
            continue

        # FIX: check each hyphen-separated segment of the registered domain.
        # Without this, "paypa1-secure" (stripped: "paypa1secure") has
        # levenshtein distance 7 from "paypal" and is missed.
        # With this, segment "paypa1" has distance 1 and is correctly flagged.
        segment_typosquat = False
        for seg in registered.split("-"):
            if len(seg) < 3:
                continue
            seg_dist = levenshtein(seg, brand_clean)
            if 0 < seg_dist <= TYPOSQUAT_EDIT_DISTANCE:
                score              = max(score, 80)
                matched            = brand
                segment_typosquat  = True
                findings.append(
                    f"Typosquatting detected: segment '{seg}' in '{registered}' "
                    f"is {seg_dist} edit(s) away from '{brand}'. "
                    f"Hyphenated domains like '{registered}.xyz' hide typosquats "
                    f"by appending '-secure' or '-login' to a misspelled brand name."
                )
                break
        if segment_typosquat:
            break

        # Also check full registered name
        dist = levenshtein(reg_clean, brand_clean)
        if 0 < dist <= TYPOSQUAT_EDIT_DISTANCE:
            score   = max(score, 80)
            matched = brand
            findings.append(
                f"Typosquatting detected: '{registered}' is {dist} edit(s) away from "
                f"'{brand}'."
            )
            break

        # Brand name appears in subdomain but not in registered domain -> injection
        if brand_clean in full_no_tld.replace("-", "") and brand_clean not in reg_clean:
            score   = max(score, 70)
            matched = brand
            findings.append(
                f"Brand keyword injection: '{brand}' appears in the subdomain of "
                f"'{domain}' but the registered domain is '{registered}'. "
                "Classic trick: 'paypal.secure-login.evil.xyz'."
            )

    if not findings:
        findings.append("No typosquatting patterns detected.")

    return {"score": score, "findings": findings, "matched_brand": matched}


# ── URL Shortener Expansion ───────────────────────────────────────────────────

def _is_shortener(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower().removeprefix("www.")
        return host in URL_SHORTENERS
    except Exception:
        return False


def _follow_redirects_sync(url: str, max_hops: int = 10) -> dict:
    """
    Follow redirect chain synchronously (runs in executor).
    Returns {'final_url': str, 'hops': int, 'chain': [str]}.
    """
    chain = [url]
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=8,
            headers={"User-Agent": "Mozilla/5.0 PhishSentinel-Scanner/2.0"},
            max_redirects=max_hops,
        ) as client:
            r = client.get(url)
            # httpx collects redirect history
            for resp in r.history:
                loc = str(resp.headers.get("location", ""))
                if loc and loc not in chain:
                    chain.append(loc)
            if str(r.url) not in chain:
                chain.append(str(r.url))
        return {"final_url": chain[-1], "hops": len(chain) - 1, "chain": chain}
    except Exception as exc:
        log.debug(f"Redirect follow failed for {url}: {exc}")
        return {"final_url": url, "hops": 0, "chain": chain}


async def expand_url(url: str) -> dict:
    """Async wrapper for redirect following."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _follow_redirects_sync, url)


# ── Main Engine ───────────────────────────────────────────────────────────────

async def run(urls: list[str]) -> dict:
    """
    Run all heuristic checks on the provided URL list.

    Returns:
        {
          "engine"          : "heuristic",
          "score"           : 0-100,
          "findings"        : [str, ...],
          "expanded_urls"   : [ {url, final_url, hops, chain}, ... ],
          "homograph_hits"  : [ {domain, matched_brand}, ... ],
          "typosquat_hits"  : [ {domain, matched_brand}, ... ],
        }
    """
    if not urls:
        return {
            "engine"        : "heuristic",
            "score"         : 0,
            "findings"      : ["No URLs provided."],
            "expanded_urls" : [],
            "homograph_hits": [],
            "typosquat_hits": [],
        }

    all_findings   = []
    max_score      = 0
    expanded_urls  = []
    homograph_hits = []
    typosquat_hits = []

    # Expand shorteners first (parallel)
    expand_tasks = [
        expand_url(url) for url in urls if _is_shortener(url)
    ]
    expansions = await asyncio.gather(*expand_tasks)
    shortener_map = {
        url: exp
        for url, exp in zip(
            [u for u in urls if _is_shortener(u)], expansions
        )
    }

    # Build final URL list (replace shorteners with their real destinations)
    effective_urls = []
    for url in urls:
        if url in shortener_map:
            exp = shortener_map[url]
            expanded_urls.append({
                "original"  : url,
                "final_url" : exp["final_url"],
                "hops"      : exp["hops"],
                "chain"     : exp["chain"],
            })
            all_findings.append(
                f"Short URL '{url}' expands to '{exp['final_url']}' "
                f"via {exp['hops']} redirect(s). Always verify the final destination."
            )
            if exp["hops"] >= 5:
                max_score = max(max_score, 60)
                all_findings.append(
                    f"Excessive redirect chain ({exp['hops']} hops) is a common "
                    "evasion tactic to bypass static URL filters."
                )
            effective_urls.append(exp["final_url"])
        else:
            effective_urls.append(url)

    # Homograph + typosquat on all effective URLs
    for url in effective_urls:
        try:
            domain = urlparse(url).netloc.lower().removeprefix("www.")
        except Exception:
            continue

        hg = check_homograph(domain)
        max_score = max(max_score, hg["score"])
        all_findings.extend(hg["findings"])
        if hg["matched_brand"]:
            homograph_hits.append({"domain": domain, "matched_brand": hg["matched_brand"]})

        ts = check_typosquat(domain)
        max_score = max(max_score, ts["score"])
        all_findings.extend(ts["findings"])
        if ts["matched_brand"]:
            typosquat_hits.append({"domain": domain, "matched_brand": ts["matched_brand"]})

    return {
        "engine"        : "heuristic",
        "score"         : round(min(max_score, 100), 1),
        "findings"      : all_findings,
        "expanded_urls" : expanded_urls,
        "homograph_hits": homograph_hits,
        "typosquat_hits": typosquat_hits,
    }