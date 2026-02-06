# Legal basis for remaining data sources

After removal of G2 (Agent 3), Twitter/X (Agent 7), and LinkedIn (Agent 8) for legal compliance, the auditor uses only the following sources.

## Safe agents and legal basis

| Agent | Source | Legal basis |
|-------|--------|-------------|
| **1. Official Page Scanner** | Target URL (e.g. vendor pricing page) | Public website; no database rights or CMA 1990 issues when scraping own target. |
| **4. Wayback Historian** | archive.org CDX / archived pages | Public archive; terms permit programmatic access for historical snapshots. |
| **5. Partner Program Researcher** | Partner programme pages (linked from target or public) | Public or licensed partner programme materials; scope limited to public-facing content. |
| **9. Public Record Scanner** | Public records (tenders, filings, open data) | Public records; no database rights or GDPR issues when using official open data. |
| **10. Consensus Validator** | Aggregates outputs of 1, 4, 5, 9 only | No direct scraping; excludes social and commercial DB inputs. |

## Removed sources (and why)

| Agent | Source | Reason removed |
|-------|--------|----------------|
| 3. G2 Review Extractor | G2.com | Database rights; commercial database; ToS and scraping risk. |
| 7. Twitter/X Tracker | Twitter/X | Computer Misuse Act; GDPR; platform ToS. |
| 8. LinkedIn Intel Gatherer | LinkedIn | CMA 1990; GDPR; professional data; ToS. |

## Consensus scoring

Consensus is computed only from:

- Official pages (agent 1)
- Public records (agent 9)
- Wayback (agent 4)
- Partner programme (agent 5)

Social media and review-site data are excluded from the consensus logic and from storage after purge.

## Compliance feature flags

- `anonymize_sources`: redact source URLs/IDs in outputs.
- `audit_trail_compliance`: retain audit trail for permitted sources only.
- `purge_social_data`: ensure no residual G2/Twitter/LinkedIn (and similar) data remains.

*Last updated: February 2025. Not legal advice.*
