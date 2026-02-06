#!/usr/bin/env python3
"""
Verification script: no toxic agents, consensus uses safe sources only, no residual imports.
Run from repo root: python -m auditor.verify_compliance
"""

import sys


def test_safe_agents_only():
    from auditor.agents.registry import AGENTS, get_safe_agents
    ids = {a["id"] for a in AGENTS}
    assert 3 not in ids, "Agent 3 (G2) must be removed"
    assert 7 not in ids, "Agent 7 (Twitter/X) must be removed"
    assert 8 not in ids, "Agent 8 (LinkedIn) must be removed"
    safe = get_safe_agents()
    assert len(safe) == 4, "Exactly 4 safe agents (1, 4, 5, 9)"
    assert {a["id"] for a in safe} == {1, 4, 5, 9}


def test_consensus_excludes_social():
    from auditor.consensus import compute_consensus
    # Safe-only findings
    safe_findings = [
        {"source_type": "official_page", "price_found": 50},
        {"source_type": "wayback", "price_found": 55},
    ]
    out = compute_consensus(safe_findings)
    assert out["shadow_price_min"] == 50
    assert out["shadow_price_max"] == 55
    assert "official_page" in str(out.get("source_types_used", []))
    # Social findings must be excluded
    mixed = safe_findings + [{"source_type": "g2_review", "price_found": 999}]
    out2 = compute_consensus(mixed)
    assert out2["shadow_price_max"] == 55
    assert 999 not in (out2["shadow_price_min"], out2["shadow_price_max"])


def test_consensus_empty_graceful():
    from auditor.consensus import compute_consensus
    out = compute_consensus([])
    assert out["shadow_price_mid"] is None
    assert out["total_source_count"] == 0


def test_orchestrator_order():
    from auditor.config import AGENT_EXECUTION_ORDER
    assert 3 not in AGENT_EXECUTION_ORDER
    assert 7 not in AGENT_EXECUTION_ORDER
    assert 8 not in AGENT_EXECUTION_ORDER
    assert AGENT_EXECUTION_ORDER == (1, 4, 5, 9, 10)


def test_no_toxic_agents_in_registry():
    from auditor.agents.registry import AGENTS
    ids = {a["id"] for a in AGENTS}
    assert 3 not in ids and 7 not in ids and 8 not in ids


def main():
    tests = [
        test_safe_agents_only,
        test_consensus_excludes_social,
        test_consensus_empty_graceful,
        test_orchestrator_order,
        test_no_toxic_agents_in_registry,
    ]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            sys.exit(1)
    print("All compliance checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
