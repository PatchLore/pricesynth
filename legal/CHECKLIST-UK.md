# Price Synth — Legal Safety Checklist (UK Focus)

**Purpose:** Launch within "data aggregation" territory only; avoid creating duty of care or professional-advice reliance.  
**Disclaimer:** This checklist is not legal advice. Have a UK solicitor review before launch.

---

## 1. Positioning & value proposition

| Check | Status | Notes |
|-------|--------|--------|
| Value prop uses "see what others pay" / "market benchmarks" only | ☐ | No "find overcharges", "detect overcharging", "recover money" |
| No auditor / compliance / recovery positioning | ☐ | Not "audit", "compliance", "recovery" in marketing or product |
| Target = procurement (negotiation prep), not dispute resolution | ☐ | Copy and UX steer toward prep, not confrontation |
| No guarantee of accuracy or completeness | ☐ | All outputs clearly "indicative", "aggregated", "not verified" |

---

## 2. Output format & labelling

| Check | Status | Notes |
|-------|--------|--------|
| Output is "benchmark data only" — no recommendations | ☐ | No "you should", "we recommend", "you are overpaying" |
| Market range shown as range only (e.g. £X–£Y), not "savings" | ☐ | See RED-FLAG-AUDIT for savings vs raw data risk |
| "Your price" shown as user-provided, not our assessment | ☐ | We don't "assess" or "evaluate" their contracts |
| Every screen with comparison data has visible disclaimer | ☐ | Short, consistent line near data |

---

## 3. Disclaimers & terms

| Check | Status | Notes |
|-------|--------|--------|
| Terms of Service: "informational only, not professional advice" | ☐ | See TERMS-DRAFT-LIABILITY.md |
| Homepage: footer/banner disclaimer present | ☐ | See UI-COPY for exact text |
| Export (PDF/CSV): disclaimer on every page / in header | ☐ | "For informational use only; not professional advice" |
| No E&O / no insurance stated in ToS (optional) | ☐ | Limitation of liability caps exposure |

---

## 4. Reliance & duty of care

| Check | Status | Notes |
|-------|--------|--------|
| No UI copy that implies we "verify" or "certify" prices | ☐ | Avoid "verified", "certified", "approved" |
| No copy that encourages confronting suppliers on our data alone | ☐ | E.g. avoid "Use this to challenge your supplier" |
| Data source attribution visible (aggregated sources, not "truth") | ☐ | "Based on aggregated data; not a substitute for your own verification" |
| Feature flags block any "advisory" outputs (see TECHNICAL-SAFEGUARDS) | ☐ | No auto-recommendations, no "you should renegotiate" |

---

## 5. Data & technical

| Check | Status | Notes |
|-------|--------|--------|
| Data source tracking in DB (audit trail for sources) | ☐ | See TECHNICAL-SAFEGUARDS.md |
| API responses avoid advisory language | ☐ | Facts only; no "recommendation" or "suggestion" fields |
| Webhooks / integrations don't auto-flag "discrepancies" as actionable | ☐ | "Variance" or "difference" only; no "overcharge" / "alert" |
| No automated emails that imply we are advising (e.g. "You may be overpaying") | ☐ | Neutral: "New market data available" |

---

## 6. Red flags to remove pre-launch

| Red flag | Action |
|----------|--------|
| Any "savings" or "overcharge" £ amount we calculate | Remove or replace with "market range" only; user does own maths |
| "Audit", "compliance", "recovery", "overcharge detection" in copy | Replace with "benchmarking", "market intelligence", "comparison" |
| Buttons/copy like "Challenge supplier" or "Dispute this" | Remove or soften to "Use in negotiation prep" |
| Implied guarantee of data accuracy | Add "indicative", "aggregated", "not verified" everywhere |
| Output that looks like a formal "report" or "assessment" | Label as "market data summary" / "benchmark summary" |

---

## 7. Pre-launch sign-off (UK)

- [ ] ToS (including liability limitation) reviewed by UK solicitor
- [ ] Homepage, dashboard, and export disclaimers in place
- [ ] Feature flags implemented to block advisory outputs
- [ ] No red-flag copy or features live
- [ ] Data source / audit trail capability in place (or documented for v1)

---

*Last updated: February 2025. Not legal advice.*
