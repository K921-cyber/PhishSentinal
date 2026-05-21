"""
PhishSentinel — WHOIS / DNS / SSL Live Verification
Run: python test_whois.py  (from any directory)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from engines.domain_engine import _whois_lookup, _dns_exists, _ssl_cert_age, is_raw_ip  # type: ignore

class C:
    P = "\033[92m✅ PASS\033[0m"
    F = "\033[91m❌ FAIL\033[0m"
    W = "\033[93m⚠️  WARN\033[0m"

def chk(label, ok, detail="", warn=False):
    tag = (C.W if warn else C.F) if not ok else C.P
    print(f"  {tag}  {label}")
    if detail: print(f"         {detail}")

print("\n" + "="*55)
print("  WHOIS / DNS / SSL Live Domain Tests")
print("="*55)

print("\n[ Raw IP Detection ]")
chk("185.220.101.5 → True",   is_raw_ip("185.220.101.5"))
chk("127.0.0.1 → True",       is_raw_ip("127.0.0.1"))
chk("::1 (IPv6) → True",      is_raw_ip("::1"))
chk("google.com → False",     not is_raw_ip("google.com"))
chk("paypal.com → False",     not is_raw_ip("paypal.com"))

print("\n[ DNS Resolution — should resolve ]")
for d in ["google.com","github.com","paypal.com"]:
    r = _dns_exists(d)
    chk(f"{d} resolves", r, detail=f"dns_exists={r}")

print("\n[ DNS Resolution — should NOT resolve ]")
for d in ["definitely-fake-domain-xyz-123.com","this-does-not-exist-phishtest.xyz"]:
    r = _dns_exists(d)
    chk(f"{d} does NOT resolve", not r, detail=f"dns_exists={r}", warn=r)

print("\n[ WHOIS Domain Age ]")
known = {"google.com":7000,"paypal.com":8000,"github.com":4000}
for domain, min_age in known.items():
    print(f"  ⏳ Querying {domain}...")
    age = _whois_lookup(domain)
    if age is None:
        chk(f"{domain} WHOIS age returned", False, detail="Timed out / blocked", warn=True)
    else:
        chk(f"{domain} age > {min_age} days", age > min_age, detail=f"age = {age} days")

print("\n[ SSL Certificate Age ]")
for domain in ["google.com","github.com"]:
    print(f"  ⏳ Checking {domain}...")
    age = _ssl_cert_age(domain)
    if age is None:
        chk(f"{domain} SSL readable", False, detail="Unreachable", warn=True)
    else:
        chk(f"{domain} cert age ≥ 1 day",  age >= 1, detail=f"cert = {age} days")
        chk(f"{domain} cert age < 400 days",age < 400,detail=f"cert = {age} days", warn=(age>=400))

print()