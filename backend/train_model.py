"""
PhishSentinel — train_model.py
ML Training Utility.

Loads email corpora → extracts features → trains TF-IDF + Random Forest
pipeline → evaluates → serializes model and vectorizer to disk.

Supported dataset formats:
  - Enron corpus  (legitimate):  plain .txt files, one email per file
  - Nazario corpus (phishing) :  plain .txt files, one email per file
  - CSV fallback              :  columns 'text' and 'label' (0=legit, 1=phish)

Usage:
    python train_model.py
    python train_model.py --csv path/to/dataset.csv
    python train_model.py --enron datasets/enron --nazario datasets/nazario
"""

import argparse
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("PhishSentinel.Train")

# ── Constants ─────────────────────────────────────────────────────────────────
MODEL_OUT      = Path("phishing_model.pkl")
VECTORIZER_OUT = Path("vectorizer.pkl")

# ── Dataset Loading ───────────────────────────────────────────────────────────

def load_txt_corpus(directory: Path, label: int) -> list[tuple[str, int]]:
    """Load all .txt files from a directory as (text, label) pairs."""
    samples = []
    if not directory.exists():
        log.warning(f"Directory not found: {directory}")
        return samples
    for path in directory.rglob("*.txt"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").strip()
            if text:
                samples.append((text, label))
        except Exception as e:
            log.debug(f"Skip {path}: {e}")
    log.info(f"Loaded {len(samples)} samples from {directory}")
    return samples


def load_csv(path: Path) -> pd.DataFrame:
    """Load dataset from CSV with 'text' and 'label' columns."""
    df = pd.read_csv(path)
    required = {"text", "label"}
    if not required.issubset(df.columns):
        raise ValueError(f"CSV must contain columns: {required}. Found: {set(df.columns)}")
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)
    log.info(f"Loaded {len(df)} rows from {path}")
    return df


def build_synthetic_data() -> pd.DataFrame:
    """
    Generate a minimal synthetic dataset when no real data is available.
    NOT suitable for production — use with real corpora.
    """
    log.warning("⚠️  Using synthetic data. For production, use real email corpora.")
    phishing = [
        "Your account has been suspended. Verify now at http://secure-login.xyz/verify",
        "URGENT: Unusual login detected. Click immediately to secure your account.",
        "Your PayPal payment failed. Update billing information to avoid account closure.",
        "Congratulations! You have won $1,000,000. Claim your prize now.",
        "Dear valued customer, your bank account will be locked. Confirm your details.",
        "Act now - your password expires in 24 hours. Login to reset.",
        "IRS FINAL NOTICE: You owe back taxes. Pay immediately to avoid arrest.",
        "Your Apple ID has been locked. Verify your information to unlock it.",
        "NETFLIX: Payment failed. Update your payment method now or lose access.",
        "Security alert: Your account was accessed from an unknown device. Verify now.",
        "You have a pending transaction. Confirm your identity to release funds.",
        "Important: Your email will be deactivated. Sign in to keep your account.",
        "Amazon: Your order cannot be processed. Update your payment information.",
        "SBI ALERT: Your net banking is blocked. Click here to unblock immediately.",
        "Your DHL package is on hold. Pay customs fee to release delivery.",
    ] * 40   # repeat for quantity

    legitimate = [
        "Hi team, please find attached the Q3 financial report for review.",
        "Reminder: Weekly standup is at 10 AM tomorrow in conference room B.",
        "Thank you for your purchase. Your order #12345 has been shipped.",
        "Please review the pull request I opened for the authentication module.",
        "The project deadline has been moved to next Friday. Please plan accordingly.",
        "Hope you are doing well. Just wanted to catch up and see how things are.",
        "Your subscription renewal is due next month. No action needed at this time.",
        "Meeting notes from yesterday's product review are attached for reference.",
        "Your Amazon order has been delivered. Rate your experience with us.",
        "Payslip for October 2024 is now available in the HR portal.",
        "The monthly newsletter: Top stories in cybersecurity this week.",
        "Your flight itinerary for Nov 15 is confirmed. Check-in opens 24 hours prior.",
        "Feedback requested: Please complete the employee satisfaction survey.",
        "Happy birthday! Wishing you a wonderful day from the whole team.",
        "Please join our webinar on cloud security best practices on Thursday.",
    ] * 40

    rows = [(t, 1) for t in phishing] + [(t, 0) for t in legitimate]
    df   = pd.DataFrame(rows, columns=["text", "label"])
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


# ── Feature Engineering ───────────────────────────────────────────────────────

def build_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        strip_accents     = "unicode",
        lowercase         = True,
        analyzer          = "word",
        ngram_range       = (1, 2),    # unigrams + bigrams
        max_features      = 15_000,
        sublinear_tf      = True,      # log(tf) smoothing
        min_df            = 2,
        stop_words        = "english",
    )


def build_classifier() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators      = 300,
        max_depth         = None,
        min_samples_leaf  = 2,
        class_weight      = "balanced",   # handles dataset imbalance
        random_state      = 42,
        n_jobs            = -1,
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PhishSentinel ML Trainer")
    parser.add_argument("--csv",     type=Path, help="Path to CSV dataset")
    parser.add_argument("--enron",   type=Path, default=Path("datasets/enron"),
                        help="Path to Enron (legitimate) corpus directory")
    parser.add_argument("--nazario", type=Path, default=Path("datasets/nazario"),
                        help="Path to Nazario (phishing) corpus directory")
    args = parser.parse_args()

    # ── Load data ────────────────────────────────────────────────────────────
    if args.csv and args.csv.exists():
        df = load_csv(args.csv)
    else:
        samples  = load_txt_corpus(args.enron, label=0)   # 0 = legitimate
        samples += load_txt_corpus(args.nazario, label=1)  # 1 = phishing

        if len(samples) < 50:
            log.warning("Fewer than 50 real samples found. Falling back to synthetic data.")
            df = build_synthetic_data()
        else:
            df = pd.DataFrame(samples, columns=["text", "label"])

    log.info(f"Dataset: {len(df)} samples | "
             f"Legitimate: {(df.label==0).sum()} | Phishing: {(df.label==1).sum()}")

    X = df["text"].tolist()
    y = df["label"].tolist()

    # ── Train / test split ───────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    # ── Vectorize ────────────────────────────────────────────────────────────
    log.info("Fitting TF-IDF vectorizer…")
    vec = build_vectorizer()
    X_train_v = vec.fit_transform(X_train)
    X_test_v  = vec.transform(X_test)

    # ── Train ─────────────────────────────────────────────────────────────
    log.info("Training Random Forest (this may take a moment)…")
    clf = build_classifier()
    clf.fit(X_train_v, y_train)

    # ── Evaluate ─────────────────────────────────────────────────────────
    y_pred    = clf.predict(X_test_v)
    acc       = (np.array(y_pred) == np.array(y_test)).mean()
    log.info(f"\n{'='*50}")
    log.info(f"Test Accuracy : {acc*100:.2f}%")
    log.info(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Legitimate','Phishing'])}")
    log.info(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    # 5-fold cross-validation
    X_all_v = vec.transform(X)
    cv_scores = cross_val_score(clf, X_all_v, y, cv=5, scoring="f1")
    log.info(f"5-Fold CV F1  : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    log.info(f"{'='*50}\n")

    # ── Serialize ─────────────────────────────────────────────────────────
    joblib.dump(clf, MODEL_OUT,      compress=3)
    joblib.dump(vec, VECTORIZER_OUT, compress=3)
    log.info(f"✅  Saved: {MODEL_OUT}  ({MODEL_OUT.stat().st_size // 1024} KB)")
    log.info(f"✅  Saved: {VECTORIZER_OUT}  ({VECTORIZER_OUT.stat().st_size // 1024} KB)")
    log.info("Ready. Start the server with:  python main.py")


if __name__ == "__main__":
    main()