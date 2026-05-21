"""
PhishSentinel — engines/ml_engine.py
Machine Learning analysis engine.
"""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy.sparse import spmatrix

log = logging.getLogger("PhishSentinel.ML")

_MODEL_PATH      = Path(__file__).parent.parent / "phishing_model.pkl"
_VECTORIZER_PATH = Path(__file__).parent.parent / "vectorizer.pkl"

_model:      Any = None
_vectorizer: Any = None


def _load_models() -> bool:
    global _model, _vectorizer
    try:
        _model      = joblib.load(_MODEL_PATH)
        _vectorizer = joblib.load(_VECTORIZER_PATH)
        log.info("✅  ML model loaded from disk.")
        return True
    except FileNotFoundError:
        log.warning("⚠️  Model files not found. Run train_model.py first.")
        return False


_loaded = _load_models()


def _top_features(vec_row: spmatrix, n: int = 5) -> list[str]:
    """Return top n trigger feature names. list() fixes reportReturnType."""
    if _model is None or _vectorizer is None:
        return []
    try:
        feature_names: list[str] = list(_vectorizer.get_feature_names_out())
        importances = _model.feature_importances_
        weights     = np.asarray(vec_row.todense()).flatten() * importances
        top_idx     = np.argsort(weights)[::-1][:n]
        return [feature_names[i] for i in top_idx if weights[i] > 0]
    except Exception:
        return []


def _unavailable() -> dict:
    return {
        "engine": "ml", "score": 50, "label": "UNAVAILABLE",
        "confidence": 0.0, "top_triggers": [],
        "findings": ["ML model not available — run train_model.py"],
    }


async def run(text: str) -> dict:
    # Explicit None guard — narrows type so Pylance stops flagging .transform()
    if _model is None or _vectorizer is None:
        return _unavailable()

    if not text.strip():
        return {
            "engine": "ml", "score": 0, "label": "NO_TEXT",
            "confidence": 0.0, "top_triggers": [],
            "findings": ["No email body text provided."],
        }

    vec        = _vectorizer.transform([text])
    proba      = _model.predict_proba(vec)[0]
    phish_prob = float(proba[1])
    score      = round(phish_prob * 100, 1)
    label      = "PHISHING" if phish_prob >= 0.50 else "LEGITIMATE"
    triggers   = _top_features(vec)

    findings = [f"ML confidence: {score:.1f}% phishing probability."]
    if triggers:
        findings.append(f"Top triggers detected: {', '.join(triggers)}.")

    return {
        "engine": "ml", "score": score, "label": label,
        "confidence": round(phish_prob, 4),
        "top_triggers": triggers, "findings": findings,
    }