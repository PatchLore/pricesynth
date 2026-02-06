"""
Compliance feature flags and safe-agent configuration.
No G2, Twitter/X, or LinkedIn. Consensus uses official pages, public records, wayback, partner only.
"""

# Safe agents only (legal basis: official pages, public archives, partner programmes, public records)
SAFE_AGENT_IDS = (1, 4, 5, 9)
CONSENSUS_AGENT_ID = 10

# Execution order: safe agents then consensus
AGENT_EXECUTION_ORDER = (*SAFE_AGENT_IDS, CONSENSUS_AGENT_ID)

# Compliance: do not use social or commercial DB sources in consensus
EXCLUDED_SOURCE_TYPES_FOR_CONSENSUS = frozenset({
    "g2_review",
    "twitter_x",
    "linkedin",
    "reddit",
    "forum",
})

# Feature flags for anonymization and compliance
COMPLIANCE_FLAGS = {
    "anonymize_sources": True,
    "audit_trail_compliance": True,
    "purge_social_data": True,
}
