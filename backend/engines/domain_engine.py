"""
PhishSentinel -- engines/domain_engine.py v2.1
FIXES:
  1. Added risk field (HIGH/MEDIUM/LOW) to analyse_url() return dict.
     Was missing -- popup.js read r.risk which was undefined -- showed ? in link table.
  2. _score_to_risk() helper converts 0-100 score to label for badge rendering.
"""

import asyncio
import ipaddress
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import whois

from config import (
    DOMAIN_AGE_HIGH_DAYS, DOMAIN_AGE_MEDIUM_DAYS,
    SSL_CERT_AGE_HIGH_DAYS, SSL_CERT_AGE_MEDIUM_DAYS,
    SUSPICIOUS_TLDS, SUBDOMAIN_DEPTH_HIGH, SUBDOMAIN_DEPTH_MEDIUM,
)

log = logging.getLogger("PhishSentinel.Domain")
_executor = ThreadPoolExecutor(max_workers=10)


def extract_domain(url: str) -> str | None:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    m = re.search(r"https?://([^/?#\s]+)", url)
    if not m:
        return None
    host = m.group(1).split(":")[0].lower()
    return host or None


def is_raw_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return "." + parts[-1] if len(parts) >= 2 else ""


def get_subdomain_depth(domain: str) -> int:
    parts = domain.split(".")
    return max(len(parts) - 2, 0)


def _score_to_risk(score: float) -> str:
    """FIX: converts score to risk label for popup link table badges."""
    if score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


def _whois_lookup(domain: str) -> int | None:
    try:
        w = whois.whois(domain)
        if isinstance(w, dict):
            created = w.get("creation_date")
        else:
            created = getattr(w, "creation_date", None)
        if isinstance(created, list):
            created = created[0]
        if created is None or not isinstance(created, datetime):
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - created).days, 0)
    except Exception as exc:
        log.debug(f"WHOIS error for {domain}: {exc}")
        return None


def _ssl_cert_age(domain: str) -> int | None:
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=5),
            server_hostname=domain,
        )
        cert = conn.getpeercert()
        conn.close()
        if not cert or "notBefore" not in cert:
            return None
        not_before_raw = cert["notBefore"]
        if not isinstance(not_before_raw, str):
            return None
        not_before = datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z")
        return (datetime.now(timezone.utc) - not_before.replace(tzinfo=timezone.utc)).days
    except Exception:
        return None


def _dns_exists(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


async def analyse_url(url: str) -> dict:
    loop = asyncio.get_event_loop()
    result: dict = {
        "url"            : url,
        "domain"         : None,
        "is_raw_ip"      : False,
        "domain_age_days": None,
        "ssl_cert_days"  : None,
        "dns_exists"     : None,
        "tld"            : None,
        "subdomain_depth": 0,
        "score"          : 0,
        "risk"           : "LOW",
        "findings"       : [],
    }

    domain = extract_domain(url)
    if not domain:
        result["findings"].append("Could not parse domain from URL.")
        result["score"] = 50
        result["risk"]  = "MEDIUM"
        return result

    result["domain"] = domain

    if is_raw_ip(domain):
        result["is_raw_ip"] = True
        result["score"]     = 100
        result["risk"]      = "HIGH"
        result["findings"].append(
            f"Raw IP address ({domain}) used directly -- bypasses all domain-reputation checks. "
            "Classic phishing evasion technique."
        )
        return result

    tld = get_tld(domain)
    result["tld"] = tld
    if tld in SUSPICIOUS_TLDS:
        result["score"] = max(result["score"], SUSPICIOUS_TLDS[tld] * 0.6)
        result["findings"].append(
            f"TLD '{tld}' is commonly abused for phishing (free/cheap registration)."
        )

    depth = get_subdomain_depth(domain)
    result["subdomain_depth"] = depth
    if depth >= SUBDOMAIN_DEPTH_HIGH:
        result["score"] = max(result["score"], 70)
        result["findings"].append(
            f"Deep subdomain nesting ({depth} levels) -- common obfuscation tactic."
        )
    elif depth >= SUBDOMAIN_DEPTH_MEDIUM:
        result["score"] = max(result["score"], 40)
        result["findings"].append(f"Elevated subdomain depth ({depth} levels).")

    dns_task   = loop.run_in_executor(_executor, _dns_exists, domain)
    whois_task = loop.run_in_executor(_executor, _whois_lookup, domain)
    ssl_task   = loop.run_in_executor(_executor, _ssl_cert_age, domain)

    dns_ok, age, ssl_age = await asyncio.gather(dns_task, whois_task, ssl_task)

    result["dns_exists"] = dns_ok
    if not dns_ok:
        result["score"] = max(result["score"], 55)
        result["findings"].append("Domain does not resolve via DNS.")

    result["domain_age_days"] = age
    if age is None:
        result["score"] = max(result["score"], 45)
        result["findings"].append("WHOIS lookup failed -- registration may be hidden.")
    elif age < DOMAIN_AGE_HIGH_DAYS:
        result["score"] = max(result["score"], 85)
        result["findings"].append(
            f"Domain is only {age} day(s) old (threshold: {DOMAIN_AGE_HIGH_DAYS} days)."
        )
    elif age < DOMAIN_AGE_MEDIUM_DAYS:
        result["score"] = max(result["score"], 50)
        result["findings"].append(f"Domain is relatively new ({age} days old).")
    else:
        result["findings"].append(f"Domain age OK ({age} days).")

    result["ssl_cert_days"] = ssl_age
    if ssl_age is None:
        result["findings"].append("SSL certificate unreachable (HTTP-only or connection refused).")
    elif ssl_age < SSL_CERT_AGE_HIGH_DAYS:
        result["score"] = max(result["score"], 65)
        result["findings"].append(
            f"SSL certificate only {ssl_age} day(s) old -- freshly provisioned cert on new domain."
        )
    elif ssl_age < SSL_CERT_AGE_MEDIUM_DAYS:
        result["score"] = max(result["score"], 35)
        result["findings"].append(f"SSL certificate relatively new ({ssl_age} days).")
    else:
        result["findings"].append(f"SSL certificate age OK ({ssl_age} days).")

    result["score"] = round(min(result["score"], 100), 1)
    result["risk"]  = _score_to_risk(result["score"])
    return result


async def run(urls: list[str]) -> dict:
    if not urls:
        return {"engine":"domain","score":0,"urls":[],"findings":["No URLs to analyse."]}
    results      = await asyncio.gather(*[analyse_url(url) for url in urls])
    worst_score  = max((r["score"] for r in results), default=0)
    all_findings = [f for r in results for f in r["findings"]]
    return {
        "engine"  : "domain",
        "score"   : round(worst_score, 1),
        "urls"    : list(results),
        "findings": all_findings,
    }