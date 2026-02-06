# Legal compliance refactor: remove high-risk scraping agents

**BREAKING CHANGE:** Agents 3 (G2), 7 (Twitter/X), 8 (LinkedIn) are removed. Consensus is based on official pages, public records, wayback, and partner sources only.

## Summary

- **Removed:** G2 Review Extractor (3), Twitter/X Tracker (7), LinkedIn Intel Gatherer (8).
- **Safe agents retained:** Official Page Scanner (1), Wayback Historian (4), Partner Program Researcher (5), Public Record Scanner (9), Consensus Validator (10).
- **Consensus:** Excludes social and commercial DB inputs; handles missing social data gracefully.
- **Database:** Purge script provided; no retention of G2/Twitter/LinkedIn data.
- **Config:** Compliance feature flags and anonymization pipeline; `.env.example` has no toxic credentials.

## If you have the legacy codebase (main.py with 10 agents)

Apply these changes for a clean diff:

### 1. Delete toxic agent code

- Remove any module or block that implements **G2 Review Extractor** (Agent 3). Delete file or function; do not comment out.
- Remove any module or block that implements **Twitter/X Tracker** (Agent 7).
- Remove any module or block that implements **LinkedIn Intel Gatherer** (Agent 8).
- Remove imports of `g2`, `twitter`, `linkedin`, `tweepy`, `linkedin-api`, or similar in the main orchestrator and agent loader.

### 2. Update orchestrator

- Replace the agent execution list with only `[1, 4, 5, 9, 10]` (or use `auditor.orchestrator.run_audit` and the registry from `auditor.agents.registry`).
- Ensure the consensus step receives only findings from agents 1, 4, 5, 9 (no 3, 7, 8).
- For frontend: keep returning 10 “slots” but mark 3, 6, 7, 8 as `deprecated: true` / inactive so the UI still works.

### 3. Consensus validator

- Refactor so it **excludes** `source_type` in `('g2_review', 'twitter_x', 'linkedin', 'reddit', 'forum')` (or your equivalent).
- When there are zero safe findings, return an empty consensus (e.g. null min/max, methodology text stating social/commercial excluded).
- Do not reference or import G2/Twitter/LinkedIn in the consensus module.

### 4. Database

- Run `migrations/purge_toxic_data.sql` (adjust table/column names to your schema).
- Ensure no table retains rows that reference agent_id 3, 7, 8 or source_type G2/Twitter/LinkedIn after purge.
- Add `compliance_flags` table or equivalent if you use the provided migration.

### 5. Environment

- Remove from `.env` and `.env.example`: G2_*, TWITTER_*, LINKEDIN_*, REDDIT_* (and any other credentials for removed agents).
- Add compliance flags if used: `COMPLIANCE_ANONYMIZE_SOURCES`, `COMPLIANCE_PURGE_SOCIAL_DATA`, etc.

### 6. Verification

- Run: `python -m auditor.verify_compliance` (from repo root). All tests must pass.
- Manually confirm: no imports of G2/Twitter/LinkedIn in the codebase; no dead code or commented-out blocks for agents 3, 7, 8.

## New compliant implementation (this repo)

The `auditor/` directory contains a clean implementation:

- `config.py` — Safe agent IDs, execution order, excluded source types for consensus.
- `agents/registry.py` — Only agents 1, 4, 5, 9, 10.
- `consensus.py` — Consensus from safe sources only; graceful empty/social-only handling.
- `orchestrator.py` — Runs only safe agents + consensus; frontend-friendly agent list.
- `anonymization.py` — Optional anonymization for compliance.
- `LEGAL_BASIS_SOURCES.md` — Legal basis for remaining sources.
- `verify_compliance.py` — Verification script.

Use this as the reference when refactoring an existing codebase or as the new auditor entrypoint.

## Expected git diff (conceptual)

- **Deleted:** Agent 3, 7, 8 implementation files; G2/Twitter/LinkedIn imports and config.
- **Added:** `auditor/` (config, registry, consensus, orchestrator, anonymization, docs, verify); `migrations/purge_toxic_data.sql`; updated `.env.example`.
- **Modified:** Main entrypoint to use `auditor.orchestrator` and safe agent list only; consensus to exclude social/commercial DB inputs; DB schema/migration for purge and flags.

No residual toxic data or dead code.
