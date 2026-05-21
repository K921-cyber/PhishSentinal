"""
PhishSentinel — Complete Test Suite v2
Fixed: 3 wrong test expectations corrected based on mathematical verification.

FIX 1 — depth test:
  "login.verify.secure.evil.xyz" has 5 labels → depth = 5-2 = 3, not 4.
  Formula: max(len(parts)-2, 0). Test was wrong.

FIX 2 — levenshtein test:
  levenshtein("xyz","paypal") = 5 exactly (not > 5).
  Changed to >= 5 and using a more clearly different pair for the > 5 test.

FIX 3 — E2E overall_score for raw IP:
  Escalation rule forces final_score = max(weighted_avg, 60).
  Raw IP alone: weighted_avg = 23.6 → escalated to 60.0 exactly.
  "score >= 90" was wrong. Correct check: score >= 60 AND escalated=True.

Run: python test_runner.py (from tests/ folder)
     or: python C:/Users/KABIR/Desktop/PhishTrace/tests/test_runner.py
"""

import asyncio
import sys
import socket
import time
from pathlib import Path

# Runtime path fix — Pylance shows reportMissingImports for these because
# it cannot evaluate sys.path at static analysis time. The imports work
# correctly at runtime. Add # type: ignore to silence Pylance if needed.
BACKEND = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(BACKEND))

class C:
    PASS = "\033[92m✅ PASS\033[0m"
    FAIL = "\033[91m❌ FAIL\033[0m"
    WARN = "\033[93m⚠️  WARN\033[0m"
    HEAD = "\033[96m"
    END  = "\033[0m"
    BOLD = "\033[1m"

results = {"pass": 0, "fail": 0, "warn": 0}

def check(name, condition, got=None, expected=None, warn_only=False):
    if condition:
        print(f"  {C.PASS}  {name}")
        results["pass"] += 1
    else:
        tag = C.WARN if warn_only else C.FAIL
        key = "warn" if warn_only else "fail"
        print(f"  {tag}  {name}")
        if got      is not None: print(f"         Got:      {got}")
        if expected is not None: print(f"         Expected: {expected}")
        results[key] += 1

def section(title):
    print(f"\n{C.HEAD}{C.BOLD}{'─'*55}\n  {title}\n{'─'*55}{C.END}")

# ═══════════════════════════════════════════════════════
# SECTION 1 — FILES
# ═══════════════════════════════════════════════════════
section("SECTION 1 — Environment & File Checks")
root = BACKEND.parent
be   = root / "backend"
ext  = root / "extension"

check("backend/main.py",            (be/"main.py").exists())
check("backend/config.py",          (be/"config.py").exists())
check("backend/scorer.py",          (be/"scorer.py").exists())
check("backend/train_model.py",     (be/"train_model.py").exists())
check("engines/ml_engine.py",       (be/"engines/ml_engine.py").exists())
check("engines/domain_engine.py",   (be/"engines/domain_engine.py").exists())
check("engines/heuristic_engine.py",(be/"engines/heuristic_engine.py").exists())
check("engines/header_engine.py",   (be/"engines/header_engine.py").exists())
check("phishing_model.pkl",         (be/"phishing_model.pkl").exists(), warn_only=True)
check("vectorizer.pkl",             (be/"vectorizer.pkl").exists(),     warn_only=True)
check("extension/manifest.json",    (ext/"manifest.json").exists())
check("extension/popup.html",       (ext/"popup.html").exists())
check("extension/popup.js",         (ext/"popup.js").exists())
check("extension/content.js",       (ext/"content.js").exists())
check("icons/icon16.png",           (ext/"icons/icon16.png").exists())
check("icons/icon48.png",           (ext/"icons/icon48.png").exists())
check("icons/icon128.png",          (ext/"icons/icon128.png").exists())

# ═══════════════════════════════════════════════════════
# SECTION 2 — CONFIG
# ═══════════════════════════════════════════════════════
section("SECTION 2 — Config Values")
try:
    from config import (WEIGHTS, VERDICT_THRESHOLDS, DOMAIN_AGE_HIGH_DAYS,  # type: ignore
                        DOMAIN_AGE_MEDIUM_DAYS, TOP_BRANDS, SUSPICIOUS_TLDS,
                        URL_SHORTENERS, TYPOSQUAT_EDIT_DISTANCE, HOMOGRAPH_MAP)

    check("WEIGHTS has all 9 keys",
          set(WEIGHTS) >= {"raw_ip","homograph","typosquat","ml","domain_age",
                           "header_auth","ssl_cert","suspicious_tld","subdomain"})
    check("raw_ip weight = 1.0",          WEIGHTS["raw_ip"] == 1.0)
    check("ml weight = 0.70",             WEIGHTS["ml"] == 0.70)
    check("HIGH threshold = 60",          VERDICT_THRESHOLDS["HIGH"] == 60)
    check("MEDIUM threshold = 35",        VERDICT_THRESHOLDS["MEDIUM"] == 35)
    check("DOMAIN_AGE_HIGH_DAYS = 30",    DOMAIN_AGE_HIGH_DAYS == 30)
    check("≥50 brands loaded",            len(TOP_BRANDS) >= 50, got=len(TOP_BRANDS))
    check("≥10 suspicious TLDs",          len(SUSPICIOUS_TLDS) >= 10)
    check(".tk in SUSPICIOUS_TLDS",       ".tk" in SUSPICIOUS_TLDS)
    check(".xyz in SUSPICIOUS_TLDS",      ".xyz" in SUSPICIOUS_TLDS)
    check("bit.ly in URL_SHORTENERS",     "bit.ly" in URL_SHORTENERS)
    check("tinyurl.com in shorteners",    "tinyurl.com" in URL_SHORTENERS)
    check("paypal in TOP_BRANDS",         "paypal" in TOP_BRANDS)
    check("google in TOP_BRANDS",         "google" in TOP_BRANDS)
    check("TYPOSQUAT distance = 2",       TYPOSQUAT_EDIT_DISTANCE == 2)
    check("HOMOGRAPH_MAP has ≥10 entries",len(HOMOGRAPH_MAP) >= 10)
except Exception as e:
    check("Config imports", False, got=str(e))

# ═══════════════════════════════════════════════════════
# SECTION 3 — SCORER
# ═══════════════════════════════════════════════════════
section("SECTION 3 — Scorer Logic")
try:
    from scorer import aggregate  # type: ignore

    r1 = aggregate({
        "ml":{"score":10,"findings":[]},"domain":{"score":15,"findings":[]},
        "heuristic":{"score":0,"findings":[]},"header":{"score":5,"findings":[]},
    })
    check("All-low → LOW",           r1["overall_risk"] == "LOW")
    check("All-low → GREEN",         r1["colour"] == "GREEN")
    check("Not escalated when low",  r1["escalated"] == False)
    check("Score in 0-100",          0 <= r1["overall_score"] <= 100)
    check("all_findings is list",    isinstance(r1["all_findings"], list))

    r2 = aggregate({
        "ml":{"score":85,"findings":[]},"domain":{"score":90,"findings":[]},
        "heuristic":{"score":80,"findings":[]},"header":{"score":70,"findings":[]},
    })
    check("All-high → HIGH",         r2["overall_risk"] == "HIGH")
    check("All-high → RED",          r2["colour"] == "RED")

    # Escalation: domain=100 (raw IP) triggers escalation
    r3 = aggregate({
        "ml":{"score":5,"findings":[]},"domain":{"score":100,"findings":[]},
        "heuristic":{"score":0,"findings":[]},"header":{"score":0,"findings":[]},
    })
    check("Escalation triggers at 100",   r3["escalated"] == True)
    check("Escalated → HIGH",            r3["overall_risk"] == "HIGH")
    # FIX: escalation only guarantees score >= 60 (the HIGH threshold)
    # weighted_avg of (5×0.70+100×0.65)/(2.75) ≈ 23.6 → escalated to 60.0
    check("Escalated score ≥ 60 (not 90)", r3["overall_score"] >= 60,
          got=f"score={r3['overall_score']}", expected="≥60")

    r4 = aggregate({
        "ml":{"score":45,"findings":[]},"domain":{"score":50,"findings":[]},
        "heuristic":{"score":30,"findings":[]},"header":{"score":20,"findings":[]},
    })
    check("Medium scores → MEDIUM or HIGH",
          r4["overall_risk"] in ("MEDIUM","HIGH"))
except Exception as e:
    check("Scorer imports", False, got=str(e))

# ═══════════════════════════════════════════════════════
# SECTION 4 — DOMAIN ENGINE FUNCTIONS
# ═══════════════════════════════════════════════════════
section("SECTION 4 — Domain Engine Functions")
try:
    from engines.domain_engine import (  # type: ignore
        extract_domain, is_raw_ip, get_tld, get_subdomain_depth, analyse_url
    )

    check("extract_domain https",   extract_domain("https://paypal.com/login") == "paypal.com")
    check("extract_domain http",    extract_domain("http://evil.xyz/phish") == "evil.xyz")
    check("extract_domain no scheme",extract_domain("evil.xyz/path") == "evil.xyz")
    check("extract_domain port",    extract_domain("http://evil.xyz:8080/path") == "evil.xyz")
    check("extract_domain empty",   extract_domain("") is None)

    check("is_raw_ip IPv4",         is_raw_ip("185.220.101.5") == True)
    check("is_raw_ip domain",       is_raw_ip("paypal.com") == False)
    check("is_raw_ip localhost",    is_raw_ip("127.0.0.1") == True)
    check("is_raw_ip IPv6",         is_raw_ip("::1") == True)

    check("get_tld .com",           get_tld("paypal.com") == ".com")
    check("get_tld .xyz",           get_tld("evil.xyz") == ".xyz")
    check("get_tld .tk",            get_tld("free.tk") == ".tk")
    check("get_tld with subdomain", get_tld("login.evil.xyz") == ".xyz")

    # FIX: depth formula = len(parts) - 2
    # "paypal.com"                 → parts=2 → depth=0
    # "login.paypal.com"           → parts=3 → depth=1
    # "a.b.c.evil.xyz"             → parts=5 → depth=3
    # "login.verify.secure.evil.xyz" → parts=5 → depth=3 (NOT 4 — test was wrong)
    check("depth paypal.com = 0",
          get_subdomain_depth("paypal.com") == 0)
    check("depth login.paypal.com = 1",
          get_subdomain_depth("login.paypal.com") == 1)
    check("depth a.b.c.evil.xyz = 3",
          get_subdomain_depth("a.b.c.evil.xyz") == 3)
    check("depth login.verify.secure.evil.xyz = 3",   # FIX: was 4, correct is 3
          get_subdomain_depth("login.verify.secure.evil.xyz") == 3,
          got=get_subdomain_depth("login.verify.secure.evil.xyz"), expected=3)
    # A genuinely 4-deep subdomain needs 6 labels total
    check("depth a.b.c.d.evil.xyz = 4",
          get_subdomain_depth("a.b.c.d.evil.xyz") == 4,
          got=get_subdomain_depth("a.b.c.d.evil.xyz"))
except Exception as e:
    check("Domain engine imports", False, got=str(e))

# ═══════════════════════════════════════════════════════
# SECTION 5 — HEURISTIC ENGINE
# ═══════════════════════════════════════════════════════
section("SECTION 5 — Heuristic Engine Functions")
try:
    from engines.heuristic_engine import (  # type: ignore
        levenshtein, check_homograph, check_typosquat, _is_shortener
    )

    check("levenshtein identical = 0",       levenshtein("paypal","paypal") == 0)
    check("levenshtein paypa1 vs paypal = 1", levenshtein("paypa1","paypal") == 1)
    check("levenshtein gooogle vs google = 1",levenshtein("gooogle","google") == 1)
    check("levenshtein arnazon vs amazon ≤ 2",levenshtein("arnazon","amazon") <= 2)
    check("levenshtein empty string = 6",    levenshtein("","paypal") == 6)

    # FIX: levenshtein("xyz","paypal") = 5 exactly (not > 5)
    # Use >= 5 to include the exact value, or use a longer difference
    d_xyz_paypal = levenshtein("xyz","paypal")
    check("levenshtein xyz vs paypal ≥ 5",
          d_xyz_paypal >= 5,
          got=f"distance={d_xyz_paypal}", expected="≥5")
    # Additional: clearly unrelated strings have high distance
    check("levenshtein abc vs microsoft > 5",
          levenshtein("abc","microsoft") > 5,
          got=levenshtein("abc","microsoft"))

    ts1 = check_typosquat("paypa1.com")
    check("typosquat paypa1.com detected", ts1["score"] > 0, got=f"score={ts1['score']}")

    ts2 = check_typosquat("gooogle.com")
    check("typosquat gooogle.com detected", ts2["score"] > 0, got=f"score={ts2['score']}")

    ts3 = check_typosquat("google.com")
    check("google.com NOT flagged as typosquat",
          ts3["matched_brand"] is None or ts3["score"] < 50,
          got=f"score={ts3['score']}, brand={ts3['matched_brand']}")

    ts4 = check_typosquat("paypal.secure-login.evil.xyz")
    check("keyword injection detected", ts4["score"] > 0, got=f"score={ts4['score']}")

    hg1 = check_homograph("paypal.com")
    check("clean domain not flagged as homograph", hg1["score"] == 0)

    check("bit.ly is shortener",       _is_shortener("http://bit.ly/abc123"))
    check("tinyurl is shortener",      _is_shortener("https://tinyurl.com/xyz"))
    check("paypal.com is NOT shortener",not _is_shortener("https://paypal.com"))
    check("google.com is NOT shortener",not _is_shortener("https://google.com"))

except Exception as e:
    check("Heuristic engine imports", False, got=str(e))

# ═══════════════════════════════════════════════════════
# SECTION 6 — HEADER ENGINE
# ═══════════════════════════════════════════════════════
section("SECTION 6 — Header Engine")

async def test_headers():
    try:
        from engines.header_engine import run  # type: ignore

        h1 = await run("Authentication-Results: spf=fail dkim=fail dmarc=fail")
        check("spf=fail → score > 0",      h1["score"] > 0, got=f"score={h1['score']}")
        check("spf parsed correctly",      h1["spf"] == "fail", got=h1["spf"])
        check("dkim parsed correctly",     h1["dkim"] == "fail", got=h1["dkim"])

        h2 = await run("Authentication-Results: spf=pass dkim=pass dmarc=pass")
        check("all pass → score < 40",     h2["score"] < 40, got=f"score={h2['score']}")
        check("spf=pass parsed",           h2["spf"] == "pass", got=h2["spf"])

        h3 = await run("")
        check("empty headers handled",
              h3["score"] == 0 and isinstance(h3["findings"], list))

        h4 = await run(
            "From: service@paypal.com\n"
            "Reply-To: attacker@gmail.com\n"
            "Authentication-Results: spf=fail"
        )
        check("Reply-To mismatch detected",
              h4["reply_to_mismatch"] == True, got=h4["reply_to_mismatch"])

    except Exception as e:
        check("Header engine runs", False, got=str(e))

asyncio.run(test_headers())

# ═══════════════════════════════════════════════════════
# SECTION 7 — ML ENGINE
# ═══════════════════════════════════════════════════════
section("SECTION 7 — ML Engine")

async def test_ml():
    try:
        from engines.ml_engine import run, _model, _vectorizer  # type: ignore

        check("ML model in RAM",      _model is not None,      warn_only=True)
        check("Vectorizer in RAM",    _vectorizer is not None, warn_only=True)
        if _model is None:
            print("  ⚠️  Skipping inference — run train_model.py first")
            return

        r1 = await run(
            "URGENT: Your PayPal account has been suspended. "
            "Click here immediately to verify your identity. "
            "Failure to act in 24 hours will result in permanent account closure. "
            "Enter your password now at the secure portal."
        )
        check("Phishing text → score > 40",
              r1["score"] > 40, got=f"score={r1['score']}, label={r1['label']}")
        check("Returns top_triggers list", isinstance(r1["top_triggers"], list))
        check("Score in 0-100",            0 <= r1["score"] <= 100)

        r2 = await run(
            "Hi team, the Q3 report is attached for your review. "
            "Meeting is at 10 AM on Thursday. Please review the agenda beforehand."
        )
        check("Legit text → score < 60",
              r2["score"] < 60, got=f"score={r2['score']}, label={r2['label']}")

        r3 = await run("")
        check("Empty text handled",
              r3["label"] in ("NO_TEXT","UNAVAILABLE","LEGITIMATE","PHISHING"))

    except Exception as e:
        check("ML engine runs", False, got=str(e))

asyncio.run(test_ml())

# ═══════════════════════════════════════════════════════
# SECTION 8 — DOMAIN ENGINE LIVE
# ═══════════════════════════════════════════════════════
section("SECTION 8 — Domain Engine Live Checks")

async def test_domain():
    try:
        from engines.domain_engine import analyse_url, run  # type: ignore

        r1 = await analyse_url("http://185.220.101.5/login")
        check("Raw IP → score=100",      r1["score"] == 100, got=f"score={r1['score']}")
        check("Raw IP → is_raw_ip=True", r1["is_raw_ip"] == True)
        check("Raw IP has findings",     len(r1["findings"]) > 0)

        r2 = await analyse_url("http://phish-test.tk/login")
        check(".tk TLD scored > 0",      r2["score"] > 0, got=f"score={r2['score']}")

        r3 = await analyse_url("http://login.verify.secure.account.evil.xyz")
        check("Deep subdomain depth ≥ 3",
              r3["subdomain_depth"] >= 3, got=f"depth={r3['subdomain_depth']}")
        check("Deep subdomain score > 0",
              r3["score"] > 0, got=f"score={r3['score']}")

        r4 = await run([])
        check("Empty list → score=0",    r4["score"] == 0)

        print("  ⏳ Live WHOIS/DNS for google.com (2-3s)...")
        r5 = await analyse_url("https://google.com")
        check("google.com DNS resolves",
              r5["dns_exists"] == True, warn_only=True)
        if r5["domain_age_days"] is not None:
            check("google.com age > 1000 days",
                  r5["domain_age_days"] > 1000, got=f"age={r5['domain_age_days']} days")
        else:
            check("WHOIS timed out (graceful)", True, warn_only=True)

    except Exception as e:
        check("Domain engine live", False, got=str(e))

asyncio.run(test_domain())

# ═══════════════════════════════════════════════════════
# SECTION 9 — E2E API
# ═══════════════════════════════════════════════════════
section("SECTION 9 — End-to-End API Integration")

def server_up():
    try:
        s = socket.create_connection(("127.0.0.1", 5000), timeout=2)
        s.close(); return True
    except: return False

if not server_up():
    print("  ⚠️  Backend not running — start: python main.py")
    print("  ⏭️  Skipping E2E tests")
else:
    import urllib.request, json, urllib.error

    def post(body):
        data = json.dumps(body).encode()
        req  = urllib.request.Request(
            "http://127.0.0.1:5000/api/scan", data=data,
            headers={"Content-Type":"application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    # Health
    try:
        with urllib.request.urlopen("http://127.0.0.1:5000/api/health", timeout=5) as r:
            h = json.loads(r.read())
        check("/health returns ok",     h.get("status") == "ok")
        check("version present",        "version" in h)
        check("all engines listed",
              all(k in h.get("engines",{}) for k in ["ml","domain","heuristic","header"]))
    except Exception as e:
        check("/health reachable", False, got=str(e))

    # Raw IP
    try:
        r1 = post({"text":"Your account is suspended. Verify now.",
                   "links":["http://185.220.101.5/login"],"raw_headers":""})
        check("Raw IP → HIGH",          r1["overall_risk"] == "HIGH",
              got=f"risk={r1['overall_risk']}, score={r1['overall_score']}")
        check("Raw IP → escalated",     r1["escalated"] == True)
        # FIX: escalation guarantees >= 60, NOT >= 90
        # domain engine returns 100, other engines near 0
        # weighted_avg ≈ 23.6, escalation bumps to exactly 60.0
        check("Raw IP score ≥ 60 (escalation threshold)",
              r1["overall_score"] >= 60,
              got=f"score={r1['overall_score']}", expected="≥60")
        check("Domain engine = 100",    r1["engine_scores"]["domain"] == 100,
              got=r1["engine_scores"]["domain"])
        check("Has all_findings",       len(r1["all_findings"]) > 0)
        check("Has detail dict",        "detail" in r1)
        check("scan_time_ms present",   "scan_time_ms" in r1)
    except Exception as e:
        check("Raw IP E2E", False, got=str(e))

    # Phishing combo
    try:
        r2 = post({"text":"Click immediately to verify your account or it will be closed.",
                   "links":["https://secure-login.tk/verify","https://paypa1.xyz/account"],
                   "raw_headers":"Authentication-Results: spf=fail dkim=none dmarc=fail"})
        check("Phishing combo → not LOW",
              r2["overall_risk"] in ("HIGH","MEDIUM"),
              got=f"risk={r2['overall_risk']}, score={r2['overall_score']}")
        check("4 engine scores present",len(r2["engine_scores"]) == 4)
        check("Header score > 0 (spf=fail)",
              r2["engine_scores"].get("header",0) > 0,
              got=r2["engine_scores"].get("header"))
    except Exception as e:
        check("Phishing combo E2E", False, got=str(e))

    # Legitimate
    try:
        r3 = post({"text":"Hi team, Q3 report attached. Review before Friday meeting.",
                   "links":["https://google.com","https://docs.google.com"],
                   "raw_headers":"Authentication-Results: spf=pass dkim=pass dmarc=pass"})
        check("Legit email → LOW or MEDIUM",
              r3["overall_risk"] in ("LOW","MEDIUM"),
              got=f"risk={r3['overall_risk']}, score={r3['overall_score']}")
        check("Header score low (spf=pass)",
              r3["engine_scores"].get("header",0) < 30,
              got=r3["engine_scores"].get("header"))
    except Exception as e:
        check("Legit email E2E", False, got=str(e))

    # Empty body
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:5000/api/scan",
            data=json.dumps({"text":"","links":[],"raw_headers":""}).encode(),
            headers={"Content-Type":"application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                check("Empty body → 400", r.getcode() == 400, got=r.getcode())
        except urllib.error.HTTPError as e:
            check("Empty body → 400", e.code == 400, got=f"HTTP {e.code}")
    except Exception as e:
        check("Empty body edge case", False, got=str(e))

# ═══════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════
total = results["pass"] + results["fail"] + results["warn"]
pct   = int(results["pass"]/total*100) if total else 0
print(f"\n{'═'*55}")
print(f"  {C.BOLD}TEST REPORT{C.END}")
print(f"{'═'*55}")
print(f"  Total   : {total}")
print(f"  \033[92mPassed\033[0m  : {results['pass']}")
print(f"  \033[91mFailed\033[0m  : {results['fail']}")
print(f"  \033[93mWarnings\033[0m: {results['warn']}")
print(f"  Score   : {pct}%")
print(f"{'═'*55}")
if results["fail"] == 0:
    print(f"\n  {C.PASS} All critical checks passed.\n")
else:
    print(f"\n  {C.FAIL} {results['fail']} failure(s). See above.\n")