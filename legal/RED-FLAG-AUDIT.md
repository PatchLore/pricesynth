# Price Synth — Red flag audit (reliance & liability)

**Goal:** Identify UI copy and features that could create reliance liability or push users into confronting suppliers on our data alone.

---

## 1. Reliance liability — what to avoid

Any copy or behaviour that implies we have **verified** data, **recommend** an action, or that the product is suitable as the **sole basis** for a decision increases reliance risk.

| Risk | Example (dangerous) | Safer alternative |
|------|--------------------|--------------------|
| We "certify" or "verify" prices | "Verified market rate", "Price verified" | "Aggregated market range", "Reported range (unverified)" |
| We tell them what to do | "You should renegotiate", "Consider switching" | No recommendation; show range only. User decides. |
| We quantify "savings" for them | "Potential savings: £5,000" | "Market range: £X–£Y. Your price: £Z." (user does maths) |
| We frame as audit/compliance | "Spend audit", "Overcharge report" | "Benchmark summary", "Market comparison" |
| We encourage confrontation | "Use this to challenge your supplier" | "Use for negotiation prep", "Context for discussions" |
| Export looks like formal advice | "Advisory report", "Recommendations" | "Market data summary", "Benchmark data only" |

**Principle:** We provide **inputs** (ranges, your number). We do not provide **outputs** (conclusions, recommendations, or "you are overpaying by X"). That keeps us in data aggregation, not professional services.

---

## 2. "Savings potential" £ amounts vs raw market data

**Higher risk:** We calculate and display a single "savings" or "overcharge" figure (e.g. "You could save £2,400/year").

- **Why risky:** It looks like a conclusion and an implicit recommendation. Users may rely on it to confront suppliers or change contracts without independent verification.
- **Mitigation:** Do **not** show a single "savings" or "overcharge" amount we compute. Show only:
  - Market range: £X–£Y  
  - Your price (as entered): £Z  
  - Optionally: "Your price vs range" (factual: above/below/mid) without a £ "savings" figure.

**Lower risk:** We show raw/benchmark data only.

- Market range: £X–£Y (sourced, aggregated, unverified).
- Your price: £Z (as entered by user).
- User does their own comparison and maths. We don’t say "you are overpaying by £W" or "savings: £W".

**Recommendation:** Implement a **feature flag** that disables any UI or export field that displays a **calculated savings/overcharge amount**. Only allow display of: (a) market range, (b) user-entered price, (c) optional neutral label like "Above/below range midpoint" (no £ figure from us).

---

## 3. Risk of users confronting suppliers based on our data

**Risk:** User takes a Price Synth export to a supplier and says "your data says I’m overpaying", creating dispute. Supplier (or user) then blames Price Synth for the dispute or outcome.

**Mitigations:**

1. **Copy:** Never encourage using the product to "challenge", "dispute", or "confront" suppliers. Use "negotiation prep", "context for discussions", "benchmarking".
2. **Export disclaimer:** Every PDF/CSV must state: "For informational use only. Not professional advice. Do not use as sole basis for disputes. Verify independently."
3. **Terms:** ToS should state that users must not hold out our data as verified or as the sole basis for confronting suppliers (see TERMS-DRAFT-LIABILITY.md).
4. **No "alert" or "flag" framing:** Don’t send emails or in-app messages like "Your price is above market — review now" or "Potential overcharge detected." Use neutral: "New market data available for your view" or "Updated benchmark range for [SKU/category]."
5. **Feature flag:** Disable any automated "discrepancy alert" or "savings opportunity" notification that implies we are advising action. Only allow neutral "data updated" type messaging.

---

## 4. Quick red-flag checklist (pre-launch)

Before launch, remove or replace:

- [ ] Any UI or email that says or implies "you are overpaying", "overcharge", "savings opportunity" (in our voice).
- [ ] Any single £ figure we calculate as "savings" or "overcharge".
- [ ] Buttons or links like "Challenge supplier", "Dispute", "Recover overcharges".
- [ ] Words: "audit", "compliance", "recovery", "verified", "certified" (in relation to our data or output).
- [ ] Export titles like "Advisory report" or "Recommendations".
- [ ] Any feature that auto-flags "discrepancy" or "overcharge" and suggests action.

---

*Not legal advice. Use with CHECKLIST-UK.md and TECHNICAL-SAFEGUARDS.md.*
