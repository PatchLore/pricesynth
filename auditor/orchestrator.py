"""
Orchestrator: runs only safe agents (1, 4, 5, 9) then Consensus (10).
Maintains API contract: frontend can receive up to 10 slots; deprecated slots 3, 6, 7, 8 are skipped.
"""

from auditor.config import AGENT_EXECUTION_ORDER, CONSENSUS_AGENT_ID
from auditor.agents.registry import get_agent_by_id
from auditor.consensus import compute_consensus

# Deprecated agent IDs (removed for compliance) — not in execution list
DEPRECATED_AGENT_IDS = {3, 6, 7, 8}


def run_audit(url: str, run_agent_fn) -> tuple[list[dict], dict]:
    """
    Run only safe agents and consensus. run_agent_fn(agent_id, url) returns finding dict.
    Returns (list of findings for each executed agent, consensus dict).
    """
    findings_by_agent: list[dict] = []
    all_findings: list[dict] = []

    for agent_id in AGENT_EXECUTION_ORDER:
        agent = get_agent_by_id(agent_id)
        if not agent:
            continue
        if agent_id == CONSENSUS_AGENT_ID:
            consensus = compute_consensus(all_findings)
            findings_by_agent.append({"agent_id": agent_id, "name": agent["name"], "consensus": consensus})
            return findings_by_agent, consensus
        result = run_agent_fn(agent_id, url)
        if result:
            result["source_type"] = agent.get("source_type", "unknown")
            all_findings.append(result)
        findings_by_agent.append({"agent_id": agent_id, "name": agent["name"], "finding": result or {}})

    consensus = compute_consensus(all_findings)
    return findings_by_agent, consensus


def get_agent_list_for_frontend():
    """
    Returns 10 slots for frontend compatibility. Slots 3, 6, 7, 8 are deprecated (removed for compliance).
    """
    return [
        {"id": 1, "name": "Official Page Scanner", "active": True},
        {"id": 2, "name": "Community Analyst", "active": False, "deprecated": True},
        {"id": 3, "name": "G2 Review Extractor", "active": False, "deprecated": True},
        {"id": 4, "name": "Wayback Historian", "active": True},
        {"id": 5, "name": "Partner Program Researcher", "active": True},
        {"id": 6, "name": "Forum Thread Analyzer", "active": False, "deprecated": True},
        {"id": 7, "name": "Twitter/X Tracker", "active": False, "deprecated": True},
        {"id": 8, "name": "LinkedIn Intel Gatherer", "active": False, "deprecated": True},
        {"id": 9, "name": "Public Record Scanner", "active": True},
        {"id": 10, "name": "Consensus Validator", "active": True},
    ]
