<div align="center">

# 🛡️ PhishSentinel

### Multi-Engine, Client-Side Phishing Detection

*Real-time. Zero cloud. Four engines firing in parallel.*

![Version](https://img.shields.io/badge/Version-2.0.2-6366f1?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11+-22c55e?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Async-00ccff?style=for-the-badge&logo=fastapi&logoColor=white)
![Chrome](https://img.shields.io/badge/Chrome-MV3-f59e0b?style=for-the-badge&logo=googlechrome&logoColor=white)


</div>

---

## Table of Contents

1. [What PhishSentinel Does](#1-what-phishsentinel-does)
2. [How It Works — Step by Step](#2-how-it-works--step-by-step)
3. [Detection Engines](#3-detection-engines)
4. [Expected Output — Every Case](#4-expected-output--every-case)
5. [Installation & Setup](#5-installation--setup)
6. [Adding Datasets & Training the Model](#6-adding-datasets--training-the-model)
7. [Terminal Output Explained](#7-terminal-output-explained)
8. [API Reference](#8-api-reference)
9. [Project Structure](#9-project-structure)
10. [Threat Model](#10-threat-model)
11. [Tech Stack](#11-tech-stack)
12. [Faculty Q&A](#12-faculty-qa)

---

## 1. What PhishSentinel Does

PhishSentinel is a **Chrome Extension** paired with a **local FastAPI backend** that scans emails for phishing signals in real time — entirely on your own machine. No data is sent to any cloud service.

### The Problem It Solves

Traditional anti-phishing tools use **reputation blocklists** (Google Safe Browsing, Microsoft SmartScreen). These fail at zero-day phishing because:

```
Hour 0  → Attacker registers secure-paypa1-login.xyz  (cost: ₹80)
Hour 0  → Provisions a free Let's Encrypt TLS cert     (30 seconds)
Hour 1  → Sends phishing emails to 500,000 people
Hour 8  → Google finally adds the domain to its blocklist
          └── 8 hours of completely unprotected exposure
```

PhishSentinel detects signals that exist **from the moment of registration** — domain age, raw IP usage, lookalike characters — not from accumulated reputation.

---

## 2. How It Works — Step by Step

```
┌─────────────────────────────────────────────────────────────┐
│                     CHROME BROWSER                           │
│                                                             │
│  Gmail / Outlook Web          PhishSentinel Popup           │
│  ┌──────────────────┐         ┌──────────────────────────┐  │
│  │                  │◄────────│  1. User clicks Scan     │  │
│  │  content.js      │         │  2. Inject content.js    │  │
│  │  ─────────────   │────────►│  3. Send {action:extract}│  │
│  │  • Read email    │         │  4. Get {text,links,hdrs}│  │
│  │    body text     │         │  5. fetch() POST →       │  │
│  │  • Collect hrefs │         │     backend              │  │
│  │  • Unwrap        │         │  6. Render verdict       │  │
│  │    redirects     │         └──────────────────────────┘  │
│  └──────────────────┘                    │                  │
└─────────────────────────────────────────|───────────────────┘
                                          │ POST /api/scan
                                          │ { text, links[], raw_headers }
                                          ▼
┌─────────────────────────────────────────────────────────────┐
│   FastAPI Backend · 127.0.0.1:5000 (loopback, LAN-isolated) │
│                                                             │
│   asyncio.gather() — all 4 engines fire simultaneously      │
│   ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────────┐  │
│   │ ML Engine│  │  Domain  │  │ Heuristic │  │ Header  │  │
│   │ RF+TFIDF │  │ WHOIS    │  │ Homograph │  │ SPF     │  │
│   │ 0-100    │  │ DNS      │  │ Typosquat │  │ DKIM    │  │
│   │ score    │  │ SSL cert │  │ Shortener │  │ DMARC   │  │
│   └────┬─────┘  └────┬─────┘  └─────┬─────┘  └────┬────┘  │
│        └─────────────┴───────────────┴──────────────┘       │
│                              │                               │
│                     scorer.aggregate()                       │
│             Weighted average + escalation rule               │
│                              │                               │
│       { overall_score, overall_risk, colour, findings[] }   │
└─────────────────────────────────────────────────────────────┘
```

### Why popup.js Does the Fetch (Not content.js)

Chrome's message-passing channel between the popup and a content script has a built-in timeout. A 2–3 second backend fetch inside `content.js` would exceed this timeout if the popup loses focus — the response arrives but the channel is already closed, producing "Failed to fetch". `popup.js` owns the `fetch()` call directly, staying alive for the full duration.

---

## 3. Detection Engines

### Engine 1 — ML Behavioural Analysis (Weight: 0.70)

**Algorithm:** TF-IDF Vectorizer → Random Forest Classifier

**How TF-IDF works:**
- Converts email text into a numerical vector of 15,000 features
- Each feature = a word or two-word phrase (unigram/bigram)
- `sublinear_tf=True` means TF = 1 + log(count) — prevents "the", "click" etc. from dominating
- `min_df=2` — ignores words appearing in fewer than 2 emails (noise reduction)

**How Random Forest works:**
- 300 decision trees, each trained on a random subset of features
- Each tree votes: phishing or legitimate
- Final answer = majority vote probability
- `class_weight="balanced"` — corrects for dataset imbalance

**What it detects:** Urgency language ("act now", "suspended"), fear triggers ("legal action", "final notice"), credential harvesting phrases ("enter your password"), impersonation patterns ("Dear valued customer").

**Real-world analogy:** Like a spam filter that has read 6,000 emails and learned which word combinations appear in phishing vs real emails.

---

### Engine 2 — Domain OSINT Forensics (Weight: 0.65)

Runs on **every link** in the email concurrently via `asyncio.gather()`.

| Check | Tool | Why It Matters |
|-------|------|----------------|
| **Raw IP detection** | `ipaddress.ip_address()` | `http://185.0.0.1/login` bypasses ALL domain reputation — no WHOIS exists for an IP |
| **Domain age** | `python-whois` WHOIS query | Phishing domains registered hours before attack. Age < 30 days = HIGH |
| **DNS existence** | `dnspython` A-record query | Ghost domain — exists in email but doesn't resolve → spoofed |
| **SSL cert age** | Live TLS handshake | Let's Encrypt certs issued in seconds. New cert on new domain = phishing infra |
| **Suspicious TLD** | Static lookup table | `.tk` `.ml` `.ga` `.xyz` `.top` — free or near-free, heavily abused |
| **Subdomain depth** | Label counting | `login.verify.secure.evil.xyz` (depth 4) hides real domain from casual inspection |

**Real-world analogy:** Like a background check on a person — you check how long they've had an ID, whether they're in the phonebook, and whether their address is real.

---

### Engine 3 — Heuristic Analysis (Weight: 0.80–0.95)

**Homograph / IDN Spoofing (Weight: 0.95)**

Attackers use Unicode characters that look identical to Latin letters:

```
рaypal.com  ← Cyrillic "р" (U+0440) — looks exactly like Latin "p"
Actual punycode: xn--aypal-kva.com

Detection process:
1. Detect xn-- punycode in domain labels
2. Decode: xn--aypal-kva.com → рaypal.com
3. NFKD normalize: maps Cyrillic р → Latin p
4. Result: paypal.com → matches brand list → SCORE = 95
```

**Typosquatting (Weight: 0.80)**

Levenshtein edit distance ≤ 2 from any of 50 known brands:

```
paypa1.com → levenshtein("paypa1", "paypal") = 1 → TYPOSQUAT
gooogle.com → levenshtein("gooogle", "google") = 1 → TYPOSQUAT
paypa1-secure.com → levenshtein("paypa1secure", "paypal") = 2 → TYPOSQUAT
```

**Keyword Injection:**
```
paypal.secure-login.evil.xyz
  ↑                    ↑
"paypal" in subdomain  registered domain = "evil.xyz"
→ KEYWORD INJECTION — score 70
```

**URL Shortener Expansion:**
```
bit.ly/xK92mZ → httpx follows redirects →
  hop 1: http://redirect.service.com/...
  hop 2: http://secure-paypa1-login.xyz/verify   ← REAL destination
→ domain engine checks the FINAL URL, not the short one
```

---

### Engine 4 — Email Header Authentication (Weight: 0.60)

**SPF (Sender Policy Framework):**
The domain's DNS records list which mail servers are authorised to send email for it. SPF=fail means the sending IP is not on that list — the sender is impersonating the domain.

**DKIM (DomainKeys Identified Mail):**
A cryptographic signature in the email header, created with the sender's private key. The public key is in DNS. DKIM=fail means the signature doesn't match — the email was forged or tampered with.

**DMARC (Domain-based Message Authentication):**
Policy that specifies what to do when SPF/DKIM fail. DMARC=fail = both SPF and DKIM failed and the domain says "this is not from us".

**Reply-To Mismatch:**
```
From: service@paypal.com
Reply-To: attacker@gmail.com
→ User replies thinking they're talking to PayPal
→ Reply goes to attacker
```

**Display-Name Spoofing:**
```
From: "PayPal Support" <noreply@evil-phish.xyz>
→ Display name says PayPal
→ Actual domain is evil-phish.xyz
→ Most users never check past the display name
```

---

## 4. Expected Output — Every Case

### Case 1: Raw IP Phishing Link
**Email contains:** `http://185.220.101.5/login/paypal`

```json
{
  "overall_risk": "HIGH",
  "colour": "RED",
  "escalated": true,
  "overall_score": 100.0,
  "engine_scores": { "ml": 65.0, "domain": 100.0, "heuristic": 0, "header": 0 },
  "all_findings": [
    "Raw IP address (185.220.101.5) used directly — bypasses all domain-reputation checks.",
    "ML confidence: 65.0% phishing probability.",
    "Top triggers detected: login, paypal, verify."
  ]
}
```
**Terminal:**
```
Scan — 142 chars | 1 link(s) | headers: no
Verdict → HIGH | Score=100.0 | 0.021s
POST /api/scan HTTP/1.1" 200 OK
```

---

### Case 2: Zero-Day Phishing Domain (3 days old)
**Email contains:** `https://secure-paypa1-login.xyz/verify`

```json
{
  "overall_risk": "HIGH",
  "colour": "RED",
  "escalated": true,
  "overall_score": 87.4,
  "engine_scores": { "ml": 78.0, "domain": 95.0, "heuristic": 80.0, "header": 0 },
  "all_findings": [
    "Domain is only 3 day(s) old — zero-day phishing domains registered hours before attacks.",
    "TLD '.xyz' is commonly abused for phishing.",
    "Typosquatting: 'paypa1' is 1 edit away from 'paypal'.",
    "SSL certificate only 3 day(s) old — freshly provisioned cert on new domain.",
    "ML confidence: 78.0% phishing probability.",
    "Top triggers detected: secure, verify, login, account."
  ]
}
```
**Terminal:**
```
Scan — 387 chars | 1 link(s) | headers: no
Verdict → HIGH | Score=87.4 | 2.341s
POST /api/scan HTTP/1.1" 200 OK
```

---

### Case 3: Homograph IDN Attack
**Email contains:** `https://рaypal.com/login` (Cyrillic р)

```json
{
  "overall_risk": "HIGH",
  "colour": "RED",
  "escalated": true,
  "overall_score": 95.0,
  "engine_scores": { "ml": 55.0, "domain": 60.0, "heuristic": 95.0, "header": 0 },
  "all_findings": [
    "IDN homograph attack: 'xn--aypal-kva.com' uses Unicode lookalike characters to impersonate 'paypal'. Normalised form: 'paypal.com'.",
    "Domain is only 12 day(s) old.",
    "SSL certificate only 12 day(s) old."
  ]
}
```

---

### Case 4: SPF/DKIM/DMARC Authentication Failure
**Email headers contain:** `spf=fail dkim=none dmarc=fail`

```json
{
  "overall_risk": "HIGH",
  "colour": "RED",
  "escalated": false,
  "overall_score": 67.2,
  "engine_scores": { "ml": 45.0, "domain": 35.0, "heuristic": 0, "header": 80.0 },
  "all_findings": [
    "SPF = 'fail': Sender identity verification failed.",
    "DKIM header not found — sender authenticity unverifiable.",
    "DMARC = 'fail': Policy violation.",
    "Reply-To domain ('attacker@gmail.com') differs from From domain ('paypal.com')."
  ]
}
```

---

### Case 5: URL Shortener Hiding Malicious Domain
**Email contains:** `bit.ly/xK92mZ` (expands to http://secure-bank-login.tk/verify)

```json
{
  "overall_risk": "HIGH",
  "colour": "RED",
  "escalated": true,
  "overall_score": 88.0,
  "engine_scores": { "ml": 60.0, "domain": 90.0, "heuristic": 70.0, "header": 0 },
  "all_findings": [
    "Short URL 'bit.ly/xK92mZ' expands to 'http://secure-bank-login.tk/verify' via 2 redirect(s).",
    "TLD '.tk' is commonly abused for phishing (score: 90).",
    "Domain is only 7 day(s) old.",
    "Domain 'secure-bank-login.tk' does not resolve via DNS."
  ]
}
```

---

### Case 6: Deep Subdomain Nesting
**Email contains:** `https://login.verify.secure.account.evil.xyz`

```json
{
  "overall_risk": "MEDIUM",
  "colour": "YELLOW",
  "escalated": false,
  "overall_score": 52.3,
  "engine_scores": { "ml": 40.0, "domain": 70.0, "heuristic": 50.0, "header": 0 },
  "all_findings": [
    "Deep subdomain nesting (4 levels) — common obfuscation tactic.",
    "TLD '.xyz' is commonly abused for phishing.",
    "Brand keyword injection: 'account' appears in subdomain of 'login.verify.secure.account.evil.xyz'."
  ]
}
```

---

### Case 7: Legitimate Email (Newsletter / Workplace)
**Email:** Regular workplace newsletter, links to skool.com, google.com

```json
{
  "overall_risk": "LOW",
  "colour": "GREEN",
  "escalated": false,
  "overall_score": 15.7,
  "engine_scores": { "ml": 17.0, "domain": 45.0, "heuristic": 0, "header": 0 },
  "all_findings": [
    "ML confidence: 17.3% phishing probability.",
    "Top triggers detected: hours, email, things, project, weekly.",
    "Domain age OK (10630 days).",
    "SSL certificate age OK (318 days).",
    "WHOIS lookup failed — registration may be hidden.",
    "No typosquatting patterns detected.",
    "No raw headers provided — authentication checks skipped."
  ]
}
```
**Terminal:**
```
Scan — 686 chars | 8 link(s) | headers: no
Verdict → LOW | Score=15.7 | 2.638s
POST /api/scan HTTP/1.1" 200 OK
```

---

### Case 8: Display-Name Spoofing
**Email From:** `"Apple Support" <noreply@apple-id-verify.ml>`

```json
{
  "overall_risk": "HIGH",
  "colour": "RED",
  "escalated": true,
  "overall_score": 82.0,
  "engine_scores": { "ml": 70.0, "domain": 85.0, "heuristic": 0, "header": 80.0 },
  "all_findings": [
    "Display-name spoofing: sender shows as 'apple support' but actual domain is 'apple-id-verify.ml'.",
    "TLD '.ml' is commonly abused for phishing.",
    "Domain is only 2 day(s) old.",
    "ML confidence: 70.0% phishing probability."
  ]
}
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.11 or newer
- Google Chrome
- Git (optional)

### Step 1 — Get the Code
```powershell
# If using Git:
git clone https://github.com/K921-cyber/Phishing_project.git
cd Phishing_project

# Or just extract the ZIP into:
# C:\Users\KABIR\Desktop\PhishTrace\
```

### Step 2 — Install Python Dependencies
```powershell
cd C:\Users\KABIR\Desktop\PhishTrace\backend
pip install fastapi "uvicorn[standard]" scikit-learn pandas joblib python-whois dnspython httpx pydantic scipy Pillow
```

### Step 3 — Get Datasets & Train the ML Model
```powershell
# Download real datasets (SpamAssassin + Enron CSV):
python download_datasets.py

# Train the Random Forest model:
python train_model.py
```

Expected training output:
```
[INFO] Dataset: 3240 samples | Legitimate: 1620 | Phishing: 1620
[INFO] Fitting TF-IDF vectorizer…
[INFO] Training Random Forest…
==================================================
Test Accuracy : 94.1%
5-Fold CV F1  : 0.942 ± 0.011
==================================================
✅  Saved: phishing_model.pkl
✅  Saved: vectorizer.pkl
Ready. Start the server with: python main.py
```

### Step 4 — Start the Server
```powershell
python main.py
```

Expected:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:5000
```

### Step 5 — Load the Chrome Extension
```
1. Chrome → chrome://extensions/
2. Toggle "Developer mode" ON (top right)
3. Click "Load unpacked"
4. Select: C:\Users\KABIR\Desktop\PhishTrace\extension\
5. Click puzzle icon → pin PhishSentinel to toolbar
```

### Step 6 — Scan an Email
```
1. Server must be running (python main.py in PowerShell — keep window open)
2. Open Gmail / Outlook Web / Yahoo Mail
3. Click on any email to open it
4. Click the PhishSentinel shield icon in toolbar
5. Click "Scan This Email"
6. Wait 2-4 seconds
```

---

## 6. Adding Datasets & Training the Model

### Method A — Automatic Download (Recommended)
```powershell
cd C:\Users\KABIR\Desktop\PhishTrace\backend
python download_datasets.py
```

This script:
1. Downloads **SpamAssassin Easy Ham** corpus (~2,500 legitimate emails)
2. Downloads **Enron Spam CSV** from GitHub (~6,000 emails, mixed)
3. If downloads fail or are insufficient, generates high-quality synthetic emails automatically
4. Reports final counts

After running, you will have:
```
backend/datasets/
├── enron/       ← legitimate emails (.txt files)
└── nazario/     ← phishing emails (.txt files)
```

### Method B — Manual CSV
If you have a CSV with columns `text` and `label` (0=legitimate, 1=phishing):
```powershell
python train_model.py --csv path\to\your\dataset.csv
```

### Method C — Manual Folder
Place `.txt` files (one email per file) into:
```
backend/datasets/enron/     ← legitimate emails
backend/datasets/nazario/   ← phishing emails
```
Then:
```powershell
python train_model.py --enron datasets\enron --nazario datasets\nazario
```

### Method D — Public Datasets (Best Accuracy)

| Dataset | Type | Where to get |
|---------|------|-------------|
| Enron Email Corpus | Legitimate | cs.cmu.edu/~enron (download full corpus) |
| SpamAssassin Public Corpus | Both | spamassassin.apache.org/old/publiccorpus/ |
| TREC 2007 Spam Track | Phishing/Spam | trec.nist.gov/data/spam.html |
| PhishTank CSV export | Phishing URLs | phishtank.org/developer_info.php |

After adding data, always retrain:
```powershell
python train_model.py
```

Model files update automatically. No server restart needed for model changes
— the next scan will use the new model automatically (restart server once
after retraining to reload from disk).

---

## 7. Terminal Output Explained

### Normal Successful Scan
```
10:59:44 [INFO] PhishSentinel — Scan — 967 chars | 7 link(s) | headers: no
           │                              │              │           │
           │                              │              │           └── No email headers extracted from DOM
           │                              │              └── 7 unique URLs found in email
           │                              └── Email body text length
           └── Timestamp

10:59:47 [INFO] PhishSentinel — Verdict → LOW | Score=16.1 | 2.838s
                                            │          │         │
                                            │          │         └── Total time for all 4 engines
                                            │          └── Weighted aggregate score (0-100)
                                            └── Final risk verdict

INFO:  127.0.0.1:48217 - "OPTIONS /api/scan HTTP/1.1" 200 OK
                          └── Browser preflight check (CORS) — always before POST

INFO:  127.0.0.1:48217 - "POST /api/scan HTTP/1.1" 200 OK
                          └── Actual scan request — 200 = success
```

### WHOIS Timeout (Normal — Not a Bug)
```
11:15:35 [ERROR] whois.whois — Error trying to connect to socket: closing socket - timed out
```
Some WHOIS servers (especially for .com TLDs like skool.com) rate-limit or are slow.
The engine handles this gracefully — returns `domain_age_days: null` and adds
"WHOIS lookup failed — registration may be hidden" to findings. Score is set to MEDIUM
for that signal. **The scan still completes.**

### Server Startup
```
INFO:     Started server process [23092]         ← OS process ID
INFO:     Waiting for application startup.        ← FastAPI initialising
INFO:     Application startup complete.           ← All engines loaded
INFO:     Uvicorn running on http://127.0.0.1:5000 (Press CTRL+C to quit)
```

### 404 on Favicon (Normal — Ignore)
```
INFO: 127.0.0.1:43334 - "GET /favicon.ico HTTP/1.1" 404 Not Found
```
Browser requests the favicon when you visit `/docs`. Not an error.

### Verify with Health Check
```powershell
curl http://127.0.0.1:5000/api/health
```
```json
{
  "status": "ok",
  "version": "2.0.2",
  "engines": {
    "ml": "ready",
    "domain": "ready",
    "heuristic": "ready",
    "header": "ready"
  }
}
```
If `ml` shows `"model_missing — run train_model.py"` → run `python train_model.py`.

---

## 8. API Reference

### `POST /api/scan`

**Request:**
```json
{
  "text"       : "Dear customer, your account has been suspended. Verify now.",
  "links"      : ["https://paypa1.com/login", "http://185.0.0.1/verify"],
  "raw_headers": "Authentication-Results: spf=fail dkim=none dmarc=fail"
}
```

**Response:**
```json
{
  "overall_score" : 87.4,
  "overall_risk"  : "HIGH",
  "colour"        : "RED",
  "escalated"     : true,
  "scan_time_ms"  : 1842,
  "engine_scores" : { "ml": 78.0, "domain": 95.0, "heuristic": 80.0, "header": 0 },
  "all_findings"  : ["Domain is only 3 day(s) old...", "..."],
  "detail"        : { "ml": {...}, "domain": {...}, "heuristic": {...}, "header": {...} }
}
```

### `GET /api/health`
Returns server status and engine readiness.

### Swagger UI (Interactive Testing)
```
http://127.0.0.1:5000/docs
```

---

## 9. Project Structure

```
PhishTrace/
│
├── backend/
│   ├── main.py                 FastAPI app, custom CORS middleware, rate limiting
│   ├── config.py               All weights, thresholds, brand lists, TLD scores
│   ├── scorer.py               Weighted aggregation + worst-case escalation
│   ├── train_model.py          ML training: TF-IDF + Random Forest + evaluation
│   ├── download_datasets.py    Downloads SpamAssassin + Enron CSV datasets
│   ├── requirements.txt        All Python dependencies
│   ├── phishing_model.pkl      Trained model (generated — excluded from git)
│   ├── vectorizer.pkl          TF-IDF vectorizer (generated — excluded from git)
│   │
│   ├── engines/
│   │   ├── ml_engine.py        Random Forest inference + feature explainability
│   │   ├── domain_engine.py    WHOIS, DNS, SSL cert, raw-IP, TLD, subdomain depth
│   │   ├── heuristic_engine.py Homograph IDN, typosquatting, URL expansion
│   │   └── header_engine.py    SPF/DKIM/DMARC, Reply-To, display-name spoofing
│   │
│   └── datasets/
│       ├── enron/              Legitimate emails (one .txt per file)
│       └── nazario/            Phishing emails (one .txt per file)
│
└── extension/
    ├── manifest.json           MV3 config — no external font CSP needed
    ├── popup.html              Clean dark UI — system fonts, no external deps
    ├── popup.js                Owns fetch(), renders verdict, animates gauge
    ├── content.js              DOM reader only — returns data, never fetches
    └── icons/
        ├── icon16.png          Generated shield icon
        ├── icon48.png          Generated shield icon
        └── icon128.png         Generated shield icon
```

---

## 10. Threat Model

### What PhishSentinel Detects

| Attack Type | Engine | Real-World Example |
|-------------|--------|-------------------|
| Zero-day phishing domain | Domain | Attacker registers `sbi-netbanking-verify.xyz` this morning |
| Raw IP phishing | Domain | Email links to `http://185.220.101.5/login` directly |
| IDN homograph spoofing | Heuristic | `рaypal.com` using Cyrillic `р` instead of Latin `p` |
| Typosquatting | Heuristic | `paypa1.com`, `gooogle.com`, `arnazon.com` |
| URL shortener concealment | Heuristic | `bit.ly/xK92` → expands to malicious domain |
| Brand keyword injection | Heuristic | `paypal.secure-login.evil.xyz` |
| Fresh SSL certificate | Domain | Let's Encrypt cert issued 2 hours ago |
| Free/abused TLD | Domain | `.tk`, `.ml`, `.ga`, `.xyz`, `.top` |
| Spoofed email sender | Header | SPF=fail, DKIM=none, DMARC=fail |
| Reply-To redirect | Header | From: paypal.com, Reply-To: attacker@gmail.com |
| Display-name fraud | Header | "PayPal Support" `<noreply@evil-phish.xyz>` |
| Redirect-hidden malicious URL | Heuristic | Gmail wraps all links via `google.com/url?q=` |

### What It Does NOT Detect
- **Aged phishing domains** (>90 days old): WHOIS age is not a signal for old domains
- **Legitimate domains serving malware**: No content/URL scanning
- **Spear phishing**: Personalised emails with no urgency language may fool ML
- **Non-email channels**: Voice (vishing) and SMS (smishing) — browser extension only

---

## 11. Tech Stack

### Backend
| Library | Version | Purpose |
|---------|---------|---------|
| FastAPI | ≥0.111 | Async REST API, auto Swagger docs |
| uvicorn | ≥0.29 | ASGI server |
| scikit-learn | ≥1.4 | TF-IDF vectorizer + Random Forest |
| pandas | ≥2.2 | Dataset loading |
| joblib | ≥1.4 | Model serialization (compressed pkl) |
| python-whois | ≥0.9.4 | Domain registration date lookup |
| dnspython | ≥2.6 | DNS A-record resolve |
| httpx | ≥0.27 | Async HTTP for redirect following |
| pydantic | ≥2.7 | Request validation |
| scipy | any | Sparse matrix support for TF-IDF |
| Pillow | any | Icon generation |

### Frontend (Chrome Extension)
| Component | Purpose |
|-----------|---------|
| Manifest V3 | Modern Chrome extension format |
| Content Scripts | Email DOM access — text, links, headers |
| popup.js | Owns fetch(), renders full verdict UI |
| System fonts | No external font CDN — works offline, no CSP issues |

---

## 12. Faculty Q&A

**Q: Why use a local server instead of a cloud API?**
A: Email content is private data. Sending it to a cloud service creates a privacy risk. The local Flask/FastAPI server on 127.0.0.1 means the email text never leaves the user's machine. It also means zero latency cost for network round trips to a remote server.

**Q: How is this different from Gmail's built-in spam filter?**
A: Gmail uses reputation-based blocklists — it compares URLs against known bad domains. PhishSentinel uses signals that exist from the moment of domain registration (WHOIS age, SSL cert age, Unicode spoofing, typosquat distance). It catches threats before they appear on any blocklist.

**Q: What is the accuracy of the ML model?**
A: ~94% on the test split of the Enron + SpamAssassin corpus. The model is not the primary detection layer — it supplements OSINT forensics. A legitimate email that triggers the ML model (false positive) will still score LOW overall if all domain forensics are clean.

**Q: What happens if the user has no internet connection?**
A: The extension and backend still work partially. WHOIS, DNS, SSL cert, and URL shortener expansion require internet. Raw IP detection, TLD scoring, subdomain depth, homograph, and typosquat checks are all offline (pure string analysis). ML inference is also offline (model loaded in RAM).

**Q: Why Manifest V3 and not V2?**
A: Google deprecated MV2 in 2024 and is removing it from Chrome. MV3 uses service workers (ephemeral) instead of persistent background pages. Content scripts must be injected via `chrome.scripting.executeScript()` rather than always-on injection.

**Q: Can this be evaded?**
A: Yes — a sophisticated attacker using a 2-year-old domain, a real SSL cert, correct SPF/DKIM, and careful language avoids most signals. No detection system is perfect. The goal is to raise the cost and complexity of attacks significantly.

**Q: Why asyncio.gather() instead of running engines sequentially?**
A: Sequential execution would make total scan time = sum of all engine times (~8s for 4 engines). `asyncio.gather()` runs them all simultaneously so total time = slowest single engine (~2-3s, bottlenecked by WHOIS). This is the async concurrency pattern from Python's standard library.

**Q: What is the Levenshtein distance?**
A: A measure of how many single-character edits (insertions, deletions, substitutions) are needed to transform one string into another. `paypa1` → `paypal` requires 1 substitution → distance = 1. We flag any registered domain within distance 2 of a known brand as a potential typosquat.

---

*PhishSentinel v2.0.2 — Built by KAPS*  
*IndiaSkills Nationals 2025-2026 · Medallion of Excellence · Skill 54: Cyber Security*  
*Shivalik College Dehradun · Thinknyx Technologies*  
*Mentors: Nitish Agrawal & Smridh Gupta*
