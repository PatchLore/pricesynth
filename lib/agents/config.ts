/**
 * Legally safe agents only. No G2, Twitter/X, LinkedIn, Reddit, or forum scrapers.
 * Consensus uses only the four data agents below.
 */

export const ACTIVE_AGENTS = [
  "official_page_scanner", // Agent 1
  "wayback_historian", // Agent 4
  "partner_program_researcher", // Agent 5
  "public_record_scanner", // Agent 9
  "consensus_validator", // Agent 10 (aggregates only the above)
] as const;

export type ActiveAgentId = (typeof ACTIVE_AGENTS)[number];

// Explicitly removed for legal compliance — do not re-add:
// 'g2_review_extractor',     // Agent 3 - Commercial database rights
// 'twitter_tracker',         // Agent 7 - CMA 1990/GDPR
// 'linkedin_intel_gatherer',  // Agent 8 - CMA 1990/GDPR
// 'reddit_analyst',          // Agent 2 - GDPR personal data
// 'forum_analyzer'           // Agent 6 - Copyright/ToS issues

export const DATA_AGENTS = ACTIVE_AGENTS.filter(
  (a) => a !== "consensus_validator"
) as readonly string[];
