# Product refactor: Competitor Shadow Audit → Public Pricing Benchmark

## Done in this repo

### 1. Product rename (landing page)
- **Title:** "Public Pricing Benchmark — Market Data Access"
- **H1:** "Public Pricing Benchmark"
- **Description:** "Automated aggregation of publicly available pricing data from official sources. Market context for negotiation preparation—not professional advice."
- **CTA button:** "Public Pricing Benchmark Access — £29"
- **Delivery:** Copy updated to "view your report online" / "access in dashboard" (no PDF-by-email as primary)

### 2. Removed / replaced language
- "Audit" → "Analysis" / "Summary" / "Benchmark" / "run"
- "Shadow" → removed; "Public" where needed
- "Competitor" → "Market" / "vendor" / "benchmarked"
- "Intelligence" → "data" / "aggregation" / "market context"
- "10-agent" → "5 legally safe data agents"
- "PDF report by email" → "access to your benchmark summary online"
- "Shadow Pricing Auditor" → "Public Pricing Benchmark" (throughout Terms, Privacy, footer)

### 3. Data sources section (added)
- **Data sources used:** Official vendor pages, Archive.org, public sector contracts, partner programme docs, aggregated consensus from public observations.
- **We do not use:** Social media (Twitter/X, LinkedIn, Reddit), commercial review DBs (G2, Capterra, TrustPilot), private forums, non-public/insider data.

### 4. Checkout disclaimer (added)
- Important notice box: automated aggregation, not audit/valuation; data from official sites and public records only; not verified; for informational use only; verify independently; no liability for decisions. Link to Terms.

### 5. Agent config (reference)
- `lib/agents/config.ts`: `ACTIVE_AGENTS` = official_page_scanner, wayback_historian, partner_program_researcher, public_record_scanner, consensus_validator. Comment documents removed agents (3, 7, 8, and optionally 2, 6).

### 6. Report disclaimer components (reference)
- `components/ReportDisclaimer.tsx`: Alert "Automated data only" + footer with Generated date, sources, "Report error" link, 30-day expiry note, and full disclaimer line for PDF/header.

### 7. Stripe
- `lib/COPY-FOR-STRIPE-DASHBOARD.md`: Instructions to rename product to "Public Pricing Benchmark Access" and suggested description.

### 8. PDF (if kept)
- `lib/pdf-disclaimer.txt`: Header/footer text for every PDF page.

---

## If you have a full Next.js app elsewhere

Apply the same renames and copy in:
- `app/page.tsx` (or landing component)
- `app/checkout/page.tsx` — add `<DisclaimerBox>` as in the prompt; product name "Public Pricing Benchmark Access"
- `app/dashboard/reports/page.tsx` — add `<ReportDisclaimer />` and `<ReportFooter />` at top and bottom
- Email templates — "Your report is ready: [View Online]" instead of attachment; link to dashboard
- PDF generator — add disclaimer header/footer to every page or remove PDF and use web-only
- `lib/agents/orchestrator.ts` — use `ACTIVE_AGENTS` from config; run only safe agents; consensus from 1, 4, 5, 9 only

Terms: keep linking to your existing liability/ToS content (e.g. from `legal/TERMS-DRAFT-LIABILITY.md`).
