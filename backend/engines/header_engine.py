"""
PhishSentinel — engines/header_engine.py
Email authentication header analysis engine.
"""

import logging
import re

log = logging.getLogger("PhishSentinel.Header")

_RE_AUTH_RESULTS  = re.compile(r"Authentication-Results:\s*(.+?)(?=\n\S|\Z)", re.S | re.I)
_RE_SPF           = re.compile(r"spf\s*=\s*(\w+)", re.I)
_RE_DKIM          = re.compile(r"dkim\s*=\s*(\w+)", re.I)
_RE_DMARC         = re.compile(r"dmarc\s*=\s*(\w+)", re.I)
_RE_FROM          = re.compile(r"^From:\s*(.+)$", re.M | re.I)
_RE_REPLY_TO      = re.compile(r"^Reply-To:\s*(.+)$", re.M | re.I)
_RE_EMAIL_EXTRACT = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
_RE_DISPLAY_NAME  = re.compile(r'^"?(.+?)"?\s*<(.+?)>', re.I)
_RE_X_MAILER      = re.compile(r"^X-Mailer:\s*(.+)$", re.M | re.I)

_BULK_MAILER_SIGS = [
    "PHPMailer", "MassMail", "SendGrid", "Mailchimp",
    "emlwizard", "Sendinblue", "Postfix", "qmail",
]

_AUTH_FAIL_VALUES = {"fail", "hardfail", "softfail", "temperror", "permerror", "none"}
_SPOOF_BRANDS     = [
    "paypal", "apple", "amazon", "google", "microsoft",
    "netflix", "facebook", "instagram", "sbi", "hdfc",
]


def _extract_domain_from_email(addr: str) -> str | None:
    m = _RE_EMAIL_EXTRACT.search(addr)
    if not m:
        return None
    return m.group().split("@")[-1].lower().strip(">")


def _parse_auth_results(headers: str) -> dict[str, str | None]:
    """
    Extract SPF/DKIM/DMARC verdicts.
    Fix: explicit dict[str, str | None] annotation so Pylance allows
    assigning a str to a value that was previously None.
    """
    # Annotated as str | None so string assignment on line 60 is valid
    results: dict[str, str | None] = {"spf": None, "dkim": None, "dmarc": None}
    m = _RE_AUTH_RESULTS.search(headers)
    if not m:
        return results
    block = m.group(1)
    for key, pattern in [("spf", _RE_SPF), ("dkim", _RE_DKIM), ("dmarc", _RE_DMARC)]:
        hit = pattern.search(block)
        if hit:
            results[key] = hit.group(1).lower()   # str assigned to str | None ✔
    return results


async def run(raw_headers: str) -> dict:
    base: dict = {
        "engine": "header", "score": 0, "findings": [],
        "spf": None, "dkim": None, "dmarc": None,
        "reply_to_mismatch": False, "display_name_spoof": False,
    }

    if not raw_headers or not raw_headers.strip():
        base["findings"].append("No raw headers provided — authentication checks skipped.")
        return base

    score:    float = 0.0
    findings: list[str] = []

    auth = _parse_auth_results(raw_headers)
    base["spf"]   = auth["spf"]
    base["dkim"]  = auth["dkim"]
    base["dmarc"] = auth["dmarc"]

    auth_failures = 0
    for proto in ("spf", "dkim", "dmarc"):
        val = auth[proto]
        if val is None:
            findings.append(f"{proto.upper()} header not found — sender authenticity unverifiable.")
            score = max(score, 20)
        elif val in _AUTH_FAIL_VALUES:
            auth_failures += 1
            score = max(score, 60 + auth_failures * 10)
            findings.append(f"{proto.upper()} = '{val}': Sender identity verification failed.")
        else:
            findings.append(f"{proto.upper()} = '{val}' ✔")

    from_match  = _RE_FROM.search(raw_headers)
    reply_match = _RE_REPLY_TO.search(raw_headers)

    if from_match and reply_match:
        from_domain  = _extract_domain_from_email(from_match.group(1))
        reply_domain = _extract_domain_from_email(reply_match.group(1))
        if from_domain and reply_domain and from_domain != reply_domain:
            base["reply_to_mismatch"] = True
            score = max(score, 75)
            findings.append(
                f"Reply-To domain ('{reply_domain}') differs from From domain ('{from_domain}'). "
                "Replies will go to attacker's mailbox."
            )

    if from_match:
        dn_match = _RE_DISPLAY_NAME.match(from_match.group(1).strip())
        if dn_match:
            display_name = dn_match.group(1).lower()
            email_domain = _extract_domain_from_email(dn_match.group(2))
            for brand in _SPOOF_BRANDS:
                if brand in display_name and email_domain and brand not in email_domain:
                    base["display_name_spoof"] = True
                    score = max(score, 80)
                    findings.append(
                        f"Display-name spoofing: sender shows as '{display_name}' "
                        f"but actual domain is '{email_domain}'."
                    )
                    break

    xm = _RE_X_MAILER.search(raw_headers)
    if xm:
        mailer = xm.group(1).strip()
        for sig in _BULK_MAILER_SIGS:
            if sig.lower() in mailer.lower():
                score = max(score, 30)
                findings.append(f"X-Mailer reveals bulk mailer: '{mailer}'.")
                break

    if not findings:
        findings.append("No suspicious header patterns detected.")

    base["score"]    = round(min(score, 100), 1)
    base["findings"] = findings
    return base