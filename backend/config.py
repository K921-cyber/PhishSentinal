"""
PhishSentinel — config.py
Central configuration: weights, thresholds, brand lists, suspicious indicators.
All magic numbers live here so tuning is a one-file job.
"""

# ── Engine Weights (0.0 – 1.0) ────────────────────────────────────────────────
# Higher = that engine's verdict pulls the final score more strongly.
WEIGHTS = {
    "raw_ip"        : 1.00,   # raw IP in URL → near-certain phishing
    "homograph"     : 0.95,   # IDN lookalike domain (е vs e, etc.)
    "typosquat"     : 0.80,   # Levenshtein-close to a known brand
    "ml"            : 0.70,   # ML Random Forest on email body text
    "domain_age"    : 0.65,   # WHOIS domain < 30 days
    "header_auth"   : 0.60,   # SPF / DKIM / DMARC fail
    "ssl_cert"      : 0.45,   # SSL cert < 30 days old or self-signed
    "suspicious_tld": 0.40,   # .xyz / .top / .tk / etc.
    "subdomain"     : 0.30,   # excessive subdomain depth (e.g. login.verify.bank.xyz)
}

# ── Verdict Thresholds ────────────────────────────────────────────────────────
VERDICT_THRESHOLDS = {
    "HIGH"  : 60,   # score ≥ 60  → RED
    "MEDIUM": 35,   # score ≥ 35  → YELLOW
    # below 35      → GREEN
}

# ── Domain Age ────────────────────────────────────────────────────────────────
DOMAIN_AGE_HIGH_DAYS   = 30    # < 30 days  → HIGH signal
DOMAIN_AGE_MEDIUM_DAYS = 90    # < 90 days  → MEDIUM signal

# ── SSL Certificate Age ───────────────────────────────────────────────────────
SSL_CERT_AGE_HIGH_DAYS   = 30
SSL_CERT_AGE_MEDIUM_DAYS = 90

# ── Subdomain Depth ───────────────────────────────────────────────────────────
SUBDOMAIN_DEPTH_HIGH   = 4   # e.g. a.b.c.evil.xyz = depth 4 (excluding TLD+1)
SUBDOMAIN_DEPTH_MEDIUM = 3

# ── Typosquatting ─────────────────────────────────────────────────────────────
TYPOSQUAT_EDIT_DISTANCE = 2   # Levenshtein ≤ 2 → flag as potential typosquat

TOP_BRANDS = [
    # Finance
    "paypal", "paypal-login", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "barclays", "lloyds", "nationwide",
    "americanexpress", "discover", "capitalone",
    # Tech
    "google", "gmail", "microsoft", "outlook", "office365",
    "apple", "icloud", "amazon", "aws", "netflix", "spotify",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "github", "gitlab", "zoom", "slack", "discord",
    # Services
    "fedex", "dhl", "ups", "usps", "royalmail",
    "ebay", "shopify", "stripe", "coinbase", "binance",
    # India-specific
    "sbi", "icici", "hdfc", "axisbank", "paytm",
    "irctc", "uidai", "incometax", "epfo",
]

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
# These TLDs are heavily abused in phishing (free or near-free registration).
SUSPICIOUS_TLDS = {
    # Score contribution out of 100
    ".tk"  : 90, ".ml"  : 85, ".ga": 85, ".cf": 85, ".gq": 85,
    ".xyz" : 70, ".top" : 70, ".icu": 65, ".buzz": 65,
    ".click": 60, ".link": 55, ".online": 50, ".site": 50,
    ".live": 45, ".info": 40, ".biz": 35,
}

# ── URL Shorteners ────────────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly", "goo.gl",
    "short.io", "cutt.ly", "rebrand.ly", "is.gd", "v.gd",
    "tiny.cc", "shorturl.at", "bl.ink", "rb.gy", "su.pr",
}

# ── Homograph Lookalikes ──────────────────────────────────────────────────────
# Map of confusable Unicode chars → their Latin equivalents.
HOMOGRAPH_MAP = {
    "\u0430": "a",  # Cyrillic а → a
    "\u0435": "e",  # Cyrillic е → e
    "\u043e": "o",  # Cyrillic о → o
    "\u0440": "r",  # Cyrillic р → r
    "\u0441": "c",  # Cyrillic с → c
    "\u0445": "x",  # Cyrillic х → x
    "\u0456": "i",  # Cyrillic і → i
    "\u0440": "p",  # Cyrillic р → p (ambiguous — rare but seen)
    "\u03b1": "a",  # Greek α → a
    "\u03b5": "e",  # Greek ε → e
    "\u03bf": "o",  # Greek ο → o
    "\u0261": "g",  # Latin script ɡ → g
    "\u0131": "i",  # Dotless i → i
    "\u0270": "m",  # Latin ɰ → m
    "\u217c": "l",  # Roman numeral small l → l
    "0"      : "o",  # digit zero → letter o
    "1"      : "l",  # digit one  → letter l
    "|"      : "l",  # pipe       → letter l
}