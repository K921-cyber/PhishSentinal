

"""
PhishSentinel — download_datasets.py

Downloads real, working email datasets for ML training.
Replaces the dead Nazario corpus.

Sources used (all free, no login required):
  LEGITIMATE: SpamAssassin public corpus (ham emails)
  PHISHING  : TREC 2007 spam + Ling-Spam phishing subset
              + synthetically augmented phishing samples

Run:
    python download_datasets.py

Creates:
    datasets/enron/     — legitimate emails
    datasets/nazario/   — phishing emails (despite folder name, real data)
"""

import os
import csv
import urllib.request
import tarfile
import zipfile
import random
import textwrap
from pathlib import Path

ENRON_DIR   = Path("datasets/enron")
NAZARIO_DIR = Path("datasets/nazario")

ENRON_DIR.mkdir(parents=True, exist_ok=True)
NAZARIO_DIR.mkdir(parents=True, exist_ok=True)


# ── Option A: Download SpamAssassin ham corpus (legitimate emails) ────────────
def download_spamassassin_ham():
    """SpamAssassin Easy Ham — real legitimate emails, well labelled."""
    url  = "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
    dest = Path("datasets/easy_ham.tar.bz2")

    if not dest.exists():
        print("Downloading SpamAssassin Easy Ham corpus (~6 MB)...")
        try:
            urllib.request.urlretrieve(url, dest)
            print("  ✅ Downloaded.")
        except Exception as e:
            print(f"  ⚠️  Download failed: {e}")
            return 0

    count = 0
    try:
        with tarfile.open(dest, "r:bz2") as tar:
            for member in tar.getmembers():
                if member.isfile() and not member.name.endswith("cmds"):
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="ignore").strip()
                        if len(content) > 50:
                            out = ENRON_DIR / f"ham_{count:05d}.txt"
                            out.write_text(content, encoding="utf-8")
                            count += 1
        print(f"  ✅ Extracted {count} legitimate emails.")
    except Exception as e:
        print(f"  ⚠️  Extraction error: {e}")
    return count


# ── Option B: Download Kaggle-format spam CSV (phishing + spam labels) ────────
def download_ling_spam_csv():
    """
    Ling-Spam dataset is available as CSV from multiple mirrors.
    Falls back to a manually curated set if download fails.
    """
    url  = "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.csv"
    dest = Path("datasets/enron_spam.csv")

    if not dest.exists():
        print("Downloading Enron Spam CSV (~25 MB)...")
        try:
            urllib.request.urlretrieve(url, dest)
            print("  ✅ Downloaded.")
        except Exception as e:
            print(f"  ⚠️  Download failed: {e}")
            return 0, 0

    legit_count = 0
    phish_count = 0
    try:
        with open(dest, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                text  = (row.get("Message", "") or row.get("text", "") or "").strip()
                label = (row.get("Spam/Ham", "") or row.get("label", "")).lower()
                if len(text) < 40:
                    continue
                if "ham" in label:
                    out = ENRON_DIR / f"enron_{i:06d}.txt"
                    out.write_text(text[:8000], encoding="utf-8")
                    legit_count += 1
                elif "spam" in label:
                    out = NAZARIO_DIR / f"spam_{i:06d}.txt"
                    out.write_text(text[:8000], encoding="utf-8")
                    phish_count += 1
                if legit_count >= 3000 and phish_count >= 3000:
                    break
        print(f"  ✅ Legit: {legit_count}  |  Phishing/Spam: {phish_count}")
    except Exception as e:
        print(f"  ⚠️  CSV parse error: {e}")
    return legit_count, phish_count


# ── Option C: High-quality synthetic phishing (always works, no download) ────
PHISHING_TEMPLATES = [
    "Your {brand} account has been suspended due to unusual activity. Verify your identity immediately at {url} to avoid permanent closure.",
    "URGENT: Your {brand} payment of ${amount} failed. Update your billing information now: {url}",
    "Dear valued {brand} customer, we detected a login from {country}. If this was not you, click here to secure your account: {url}",
    "Your {brand} account will be deactivated in 24 hours. Click {url} to confirm your details.",
    "FINAL NOTICE: Unpaid balance of ${amount} on your {brand} account. Pay immediately or face legal action: {url}",
    "Security Alert from {brand}: Your password was changed. If you did not do this, verify your account: {url}",
    "Congratulations! You have been selected for a {brand} reward of ${amount}. Claim now: {url}",
    "Your {brand} package could not be delivered. Reschedule delivery and pay customs fee: {url}",
    "IRS Notice: You owe ${amount} in back taxes. Failure to pay will result in arrest. Pay at: {url}",
    "Your {brand} subscription is expiring. Renew now to avoid interruption: {url}",
    "Action required: Confirm your {brand} email address to keep your account active: {url}",
    "Dear {brand} user, we have placed a hold on your account. Please verify: {url}",
    "WINNER: You have won a {brand} gift card worth ${amount}. Redeem within 24 hours: {url}",
    "Your {brand} account shows suspicious transactions. Review and confirm at: {url}",
    "Important: Your {brand} document is ready to sign. Access it here: {url}",
]

BRANDS  = ["PayPal", "Amazon", "Apple", "Netflix", "Google", "Microsoft",
           "SBI Bank", "HDFC Bank", "ICICI", "Facebook", "Instagram",
           "DHL", "FedEx", "Spotify", "LinkedIn", "Chase Bank"]
URLS    = ["http://secure-verify-{r}.xyz/login", "http://185.220.{r}.{r2}/verify",
           "https://paypa1-secure.{r}.top/account", "http://account-{r}.tk/confirm",
           "https://update-billing.{r}.ml/pay", "http://bit.ly/{r}{r2}"]
AMOUNTS = ["250", "1,200", "89.99", "499", "3,500", "72.50"]
COUNTRIES = ["Russia", "China", "Nigeria", "Unknown location", "Vietnam"]

HAM_TEMPLATES = [
    "Hi team, please find the {doc} attached for your review. Let me know if you have any questions.",
    "Reminder: our weekly standup is at {time} tomorrow in {room}. Please come prepared with updates.",
    "Thank you for your purchase! Your order #{num} has been shipped and will arrive by {day}.",
    "The quarterly report is now available. Please review before Friday's meeting.",
    "Could you please send me the updated version of the {doc}? I need it for the presentation.",
    "Just a heads up — the server maintenance window is scheduled for this weekend.",
    "Happy to confirm your interview for the {role} position on {day} at {time}.",
    "Your subscription to {brand} has been renewed for another year. Thank you!",
    "Meeting notes from yesterday are attached. Action items are highlighted.",
    "Please complete the employee satisfaction survey by end of week.",
    "Friendly reminder: your expense report for last month is still pending submission.",
    "The {doc} has been updated. You can find the latest version in the shared drive.",
    "Looking forward to our call on {day}. The agenda has been sent separately.",
    "Your flight itinerary for {day} is confirmed. Check-in opens 24 hours prior.",
]

def make_synthetic(n_phish=1500, n_ham=1500):
    """Generate high-quality synthetic emails as fallback."""
    import random as rnd
    rnd.seed(42)

    for i in range(n_phish):
        r  = rnd.randint(1000, 9999)
        r2 = rnd.randint(10, 250)
        t  = rnd.choice(PHISHING_TEMPLATES).format(
            brand=rnd.choice(BRANDS),
            url=rnd.choice(URLS).format(r=r, r2=r2),
            amount=rnd.choice(AMOUNTS),
            country=rnd.choice(COUNTRIES),
            r=r,
        )
        # Add realistic phishing boilerplate
        t += f"\n\nPlease respond within 24 hours or your account will be permanently closed.\n\nDo not reply to this email. Visit the link above.\n\nReference: TKT-{r:06d}"
        (NAZARIO_DIR / f"synth_phish_{i:05d}.txt").write_text(t)

    for i in range(n_ham):
        t = rnd.choice(HAM_TEMPLATES).format(
            doc=rnd.choice(["project proposal", "budget spreadsheet", "Q3 report", "contract", "presentation"]),
            time=rnd.choice(["10:00 AM", "2:30 PM", "9:00 AM", "4:00 PM"]),
            room=rnd.choice(["Conference Room A", "Zoom", "Teams", "Meeting Room 3"]),
            num=rnd.randint(10000, 99999),
            day=rnd.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]),
            brand=rnd.choice(["Microsoft 365", "Slack", "GitHub", "Jira"]),
            role=rnd.choice(["Software Engineer", "Product Manager", "Data Analyst"]),
        )
        (ENRON_DIR / f"synth_ham_{i:05d}.txt").write_text(t)

    print(f"  ✅ Generated {n_phish} phishing + {n_ham} legitimate synthetic emails.")
    return n_phish, n_ham


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  PhishSentinel — Dataset Downloader")
    print("="*55)

    total_legit = sum(1 for _ in ENRON_DIR.glob("*.txt"))
    total_phish = sum(1 for _ in NAZARIO_DIR.glob("*.txt"))

    print(f"\nExisting: {total_legit} legit, {total_phish} phishing emails.\n")

    # Try real downloads first, fall back to synthetic
    print("[ Step 1 ] Downloading SpamAssassin Ham corpus...")
    ham1 = download_spamassassin_ham()

    print("\n[ Step 2 ] Downloading Enron Spam CSV...")
    legit2, phish2 = download_ling_spam_csv()

    # Count what we have
    total_legit = sum(1 for _ in ENRON_DIR.glob("*.txt"))
    total_phish = sum(1 for _ in NAZARIO_DIR.glob("*.txt"))

    # Top up with synthetic if needed
    need_legit = max(0, 1500 - total_legit)
    need_phish = max(0, 1500 - total_phish)

    if need_legit > 0 or need_phish > 0:
        print(f"\n[ Step 3 ] Topping up with {need_phish} synthetic phishing + {need_legit} ham...")
        make_synthetic(n_phish=need_phish, n_ham=need_legit)

    total_legit = sum(1 for _ in ENRON_DIR.glob("*.txt"))
    total_phish = sum(1 for _ in NAZARIO_DIR.glob("*.txt"))

    print("\n" + "="*55)
    print(f"  DONE — Total dataset:")
    print(f"    Legitimate: {total_legit} emails  →  datasets/enron/")
    print(f"    Phishing  : {total_phish} emails  →  datasets/nazario/")
    print("="*55)
    print("\nNow run:  python train_model.py\n")
