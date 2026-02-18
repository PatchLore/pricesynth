# Public Pricing Benchmark — Legal safeguards summary

This document summarises what is in place to reduce the risk of legal complaints and to keep the service clearly in **data aggregation** territory (not professional advice, auditing, or advisory services).

**This is not legal advice.** Have a UK solicitor review your Terms and positioning before or after launch.

---

## 1. Product positioning and naming

- **Product name:** “Public Pricing Benchmark” (no “audit”, “shadow”, or “competitor”).
- **Description:** Automated aggregation of publicly available pricing data from official sources; market context for negotiation preparation—**not professional advice**.
- **Delivery:** Secure web report within 24 hours (no “PDF audit” or “intelligence report”).
- **Stripe:** Product and description use the same safe language (see `lib/COPY-FOR-STRIPE-DASHBOARD.md`).

---

## 2. Data sources — transparency and limits

**Allowed sources (stated on the site):**

- Official vendor pricing pages (publicly accessible, robots.txt compliant).
- Archive.org historical snapshots (public domain).
- UK Contracts Finder and EU TED public tender databases (Open Government Licence).
- Published partner program documentation / publicly accessible partner program directories (no login required).

**Explicitly not used (stated on the site):**

- Social media (Twitter/X, LinkedIn).
- Commercial review databases (e.g. G2, Capterra).
- Private forums or any data requiring authentication.

This keeps the service clearly based on **public, attributable** sources and avoids reliance on scraped social or review data.

---

## 3. Backend / analysis pipeline

- **Compliant auditor** (`auditor/`): Only four “safe” agents (official page, Wayback, partner, public records). High-risk agents (G2, Twitter/X, LinkedIn, etc.) removed.
- **Consensus:** Built only from these safe sources; no mixing with removed agents.
- **DB and migrations:** Purge of toxic/high-risk data; compliance flags and anonymisation where relevant (see `migrations/purge_toxic_data.sql`, `auditor/`).
- **No “10 agents” claims:** Copy refers to “4 verified public sources” / “automated data aggregation”, not a 10-agent system.

---

## 4. Terms and Conditions (on the site)

- **Governing law:** England and Wales; exclusive jurisdiction of the courts of England and Wales.
- **No duty of care:** Stated in Section 1 (Service Description) that Public Pricing Benchmark operates as a data aggregation tool only; no advisory, professional, or fiduciary relationship; **no duty of care** regarding any decision the user makes using the data.
- **No insurance:** Stated in Section 5 (Limitation of Liability) that Public Pricing Benchmark does not maintain professional indemnity or errors & omissions insurance; user acknowledges they use the service with full knowledge of this limitation.
- **Partner documentation:** Clarified as “publicly accessible partner program directories (no login required)” to avoid implying access to non-public or login-gated materials.
- **Informational use only:** Data is for informational use only; not verified; not professional advice; user responsible for their own decisions.

---

## 5. Privacy and contact

- **Contact email:** support@pricesynth.com (no personal/legacy addresses in public-facing legal text).
- **Brand:** “Public Pricing Benchmark” used consistently in Terms and Privacy (no “Shadow Pricing Auditor” or old names in those sections).
- **Privacy Policy:** Last Updated date and Contact (support@pricesynth.com) shown in the policy.

---

## 6. UI and copy

- **Hero and CTA:** “Order Public Pricing Benchmark — £29”; “product/pricing page URL you want analyzed” (no “competitor URL”).
- **Data sources box:** Short list of sources and “We do NOT use” list on the homepage.
- **FAQs:**  
  - “Is this legal?” — bullet list of sources, explicit “We do NOT use”, and “informational purposes only; does not constitute professional advice, auditing, or verification.”  
  - “How accurate?” — “We do not verify, audit, or guarantee”; “informational context for negotiation preparation, not a substitute for due diligence.”  
  - “What format?” — Web-based report; “We do not provide recommendations or advice on specific negotiations.”
- **Footer:** “Price Synth provides automated aggregation of publicly available pricing data only. Not professional advice. Not audited. Not verified.” Plus data sources and “verify all information independently before use.”
- **Report/dashboard copy:** Disclaimers on every view; no “savings” or “you are overpaying by X” style conclusions (see `legal/UI-COPY-HOMEPAGE-DASHBOARD-EXPORT.md` and `components/ReportDisclaimer.tsx` where used).

---

## 7. Legal package (reference only)

The `legal/` folder holds supporting materials (not published as the live Terms/Privacy):

- **CHECKLIST-UK.md** — Pre-launch legal safety checklist.
- **TERMS-DRAFT-LIABILITY.md** — Draft ToS liability clauses (no duty of care, limitation of liability, UK).
- **UI-COPY-HOMEPAGE-DASHBOARD-EXPORT.md** — Safe wording for homepage, dashboard, and exports.
- **RED-FLAG-AUDIT.md** — Reliance liability, “savings” vs raw data, users confronting suppliers.
- **TECHNICAL-SAFEGUARDS.md** — Audit trail, API/webhook safety, feature flags to block advisory outputs.

---

## 8. Core principle (for ongoing changes)

**We provide inputs (aggregated public data, ranges, your price). We do not provide outputs (conclusions, recommendations, or “you are overpaying by X”).** That keeps the product in data aggregation, not professional services, and supports the disclaimers and Terms in place to guard against legal complaints.

---

*Last updated: February 2026*
