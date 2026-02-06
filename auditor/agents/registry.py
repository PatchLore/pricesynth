"""
Registry of safe agents only. Agents 3 (G2), 7 (Twitter/X), 8 (LinkedIn) removed for legal compliance.
"""

from auditor.config import SAFE_AGENT_IDS, CONSENSUS_AGENT_ID

AGENTS = [
    {"id": 1, "name": "Official Page Scanner", "source_type": "official_page"},
    {"id": 4, "name": "Wayback Historian", "source_type": "wayback"},
    {"id": 5, "name": "Partner Program Researcher", "source_type": "partner_program"},
    {"id": 9, "name": "Public Record Scanner", "source_type": "public_record"},
    {"id": CONSENSUS_AGENT_ID, "name": "Consensus Validator", "source_type": "synthesis"},
]


def get_safe_agents():
    return [a for a in AGENTS if a["id"] in SAFE_AGENT_IDS]


def get_agent_by_id(agent_id: int):
    for a in AGENTS:
        if a["id"] == agent_id:
            return a
    return None
