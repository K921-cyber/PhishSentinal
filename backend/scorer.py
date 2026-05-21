"""
PhishSentinel — scorer.py
Weighted verdict aggregation.

Each engine returns a 0-100 score.  The final threat score is a
weighted average, but with a "worst-case escalation" rule:
  • Any single engine at 90+  escalates overall to HIGH.
  • This prevents a low-scoring engine from diluting a clear signal.

Final score → verdict:
  ≥ 60  → HIGH   (RED)
  ≥ 35  → MEDIUM (YELLOW)
  < 35  → LOW    (GREEN)
"""

from config import WEIGHTS, VERDICT_THRESHOLDS


def aggregate(engine_results: dict) -> dict:
    """
    Parameters
    ----------
    engine_results : dict
        Keys are engine names; values are the dicts returned by each engine.
        Expected keys per engine result: "score" (0-100), "findings" (list[str]).

    Returns
    -------
    dict with:
        overall_score   : float   — final 0-100 threat score
        overall_risk    : str     — HIGH / MEDIUM / LOW
        colour          : str     — RED / YELLOW / GREEN
        engine_scores   : dict    — per-engine score for the UI breakdown bars
        all_findings    : list    — flat list of all findings across engines
        escalated       : bool    — True if worst-case rule triggered
    """
    weighted_sum  = 0.0
    weight_total  = 0.0
    engine_scores = {}
    all_findings  = []
    escalated     = False

    for engine_name, result in engine_results.items():
        raw_score = float(result.get("score", 0))
        weight    = WEIGHTS.get(engine_name, 0.50)

        weighted_sum      += raw_score * weight
        weight_total      += weight
        engine_scores[engine_name] = round(raw_score, 1)
        all_findings.extend(result.get("findings", []))

        # Worst-case escalation
        if raw_score >= 90:
            escalated = True

    if weight_total == 0:
        overall_score = 0.0
    else:
        overall_score = weighted_sum / weight_total

    # Apply escalation: force at least HIGH threshold
    if escalated:
        overall_score = max(overall_score, float(VERDICT_THRESHOLDS["HIGH"]))

    overall_score = round(min(overall_score, 100.0), 1)

    # Map score → risk
    if overall_score >= VERDICT_THRESHOLDS["HIGH"]:
        risk   = "HIGH"
        colour = "RED"
    elif overall_score >= VERDICT_THRESHOLDS["MEDIUM"]:
        risk   = "MEDIUM"
        colour = "YELLOW"
    else:
        risk   = "LOW"
        colour = "GREEN"

    return {
        "overall_score" : overall_score,
        "overall_risk"  : risk,
        "colour"        : colour,
        "engine_scores" : engine_scores,
        "all_findings"  : all_findings,
        "escalated"     : escalated,
    }