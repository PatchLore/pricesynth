"""
Consensus Validator: aggregates only safe-agent outputs.
Excludes social media and commercial DB sources (G2, Twitter, LinkedIn, Reddit, forums).
"""

from auditor.config import EXCLUDED_SOURCE_TYPES_FOR_CONSENSUS


def compute_consensus(findings: list[dict]) -> dict:
    """
    Build consensus from findings. Only includes inputs from safe source types.
    Handles missing social data gracefully (no dependency on agents 3, 7, 8).
    """
    safe = [
        f for f in findings
        if (f.get("source_type") or "").lower() not in EXCLUDED_SOURCE_TYPES_FOR_CONSENSUS
    ]
    if not safe:
        return _empty_consensus()

    prices = []
    for f in safe:
        p = f.get("price_found") or f.get("estimated_mid")
        if p is not None:
            try:
                prices.append(float(p))
            except (TypeError, ValueError):
                pass

    if not prices:
        return _empty_consensus()

    prices.sort()
    low = min(prices)
    high = max(prices)
    mid = (low + high) / 2
    n = len(prices)

    return {
        "shadow_price_min": low,
        "shadow_price_max": high,
        "shadow_price_mid": mid,
        "confidence": _confidence_from_count(n),
        "total_source_count": sum(int(f.get("source_count") or 1) for f in safe),
        "methodology": "Consensus from official pages, public records, wayback, and partner sources only. Social and review-site data excluded for compliance.",
        "source_types_used": list({f.get("source_type") for f in safe if f.get("source_type")}),
    }


def _confidence_from_count(n: int) -> float:
    if n >= 4:
        return 0.8
    if n >= 2:
        return 0.6
    return 0.4


def _empty_consensus() -> dict:
    return {
        "shadow_price_min": None,
        "shadow_price_max": None,
        "shadow_price_mid": None,
        "confidence": 0.0,
        "total_source_count": 0,
        "methodology": "No safe-source data available. Social and review-site sources excluded for compliance.",
        "source_types_used": [],
    }
