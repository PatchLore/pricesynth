# Price Synth — Technical safeguards & feature flags

**Goal:** Support "data aggregation only" positioning with audit trails, neutral API/export language, and feature flags that block advisory outputs.

---

## 1. Database schema — data source tracking (audit trail)

Track provenance so you can show "aggregated from these sources" and defend that you are not vouching for any one source.

**Suggested additions:**

```sql
-- Example: fact table for price observations
ALTER TABLE price_observations ADD COLUMN source_id VARCHAR(64);      -- e.g. "public_api_2024", "license_xyz"
ALTER TABLE price_observations ADD COLUMN source_type VARCHAR(32);   -- e.g. "public", "licensed", "user_submitted"
ALTER TABLE price_observations ADD COLUMN ingested_at TIMESTAMPTZ;
ALTER TABLE price_observations ADD COLUMN source_metadata JSONB;      -- optional: URL, licence, version

-- Optional: sources reference table
CREATE TABLE data_sources (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255),
  type VARCHAR(32),
  licence_or_terms TEXT,
  last_updated_at TIMESTAMPTZ
);
```

**Use:** In exports and (if needed) in UI, you can show "Based on aggregated data from [source types]" without implying we verified each figure. Supports "we aggregate; we don’t certify."

---

## 2. API response structure — avoid advisory language

**Do not return:**

- `recommendation`, `suggestion`, `advice`, `action_required`
- `overcharge`, `savings_amount`, `potential_savings`
- `alert`, `discrepancy_flag` (if framed as "you should act")

**Do return (factual / data-only):**

- `market_range_low`, `market_range_high` (or equivalent)
- `user_price` (as submitted by the client)
- `data_sources` or `source_ids` (for transparency)
- `as_of_date` or `generated_at`
- Optional: `position_vs_range` as an enum: e.g. `"above_range" | "below_range" | "within_range"` with no £ figure from the API

**Example safe payload shape:**

```json
{
  "sku_id": "...",
  "market_range": { "low": 100, "high": 150, "currency": "GBP" },
  "user_price": 180,
  "user_price_as_entered": true,
  "position_vs_range": "above_range",
  "sources_summary": { "count": 12, "types": ["public", "licensed"] },
  "generated_at": "2025-02-02T12:00:00Z",
  "disclaimer": "Aggregated data for informational use only. Not professional advice."
}
```

Omit any field like `savings_amount`, `recommendation`, or `alert_level`.

---

## 3. Webhooks / integration payloads — no auto‑flagging as "action required"

**Risk:** Integrations that send "discrepancy detected" or "potential overcharge" push you into advisory territory and can trigger users to act on our data alone.

**Safeguards:**

- **Payload:** Send only factual data (e.g. updated market range, new data for SKU). Do **not** include:
  - `recommendation`, `action`, `alert_type`, `overcharge`, `savings`
- **Naming:** Use neutral event names, e.g. `market_data.updated`, `benchmark.refreshed`, not `discrepancy.alert` or `overcharge.detected`.
- **Docs:** State in integration docs that payloads are "informational only; not a recommendation to act."

**Example safe webhook payload:**

```json
{
  "event": "market_data.updated",
  "sku_id": "...",
  "market_range": { "low": 100, "high": 150, "currency": "GBP" },
  "updated_at": "2025-02-02T12:00:00Z",
  "disclaimer": "Informational only. Not professional advice."
}
```

---

## 4. Feature flags to implement now (block advisory outputs)

Implement flags so you can **disable** any feature that could be read as advice or overcharge detection, without a full redeploy.

| Flag name | Purpose | Default (pre‑insurance) |
|-----------|---------|---------------------------|
| `show_savings_amount` | Show any single £ "savings" or "overcharge" we calculate | **OFF** |
| `show_recommendations` | Any UI/API text like "consider renegotiating" or "we recommend" | **OFF** |
| `discrepancy_alerts` | Push/email that frames variance as "alert" or "action required" | **OFF** |
| `export_include_savings_column` | PDF/CSV column with "Potential savings" or "Overcharge" £ | **OFF** |
| `neutral_data_only` | When ON, enforce: range + user price only; no derived advisory fields | **ON** |

**Behaviour:**

- With `show_savings_amount` OFF: never render or return a £ figure we compute as "savings" or "overcharge". Only show market range and user-entered price.
- With `discrepancy_alerts` OFF: any "variance" or "difference" is shown only as data (e.g. "Your price vs range"); no email/push that says "review this" or "potential overcharge".
- With `neutral_data_only` ON: API and UI exclude recommendation/savings/alert fields even if added later in code.

**Implementation note:** In config or env, e.g.:

```bash
# Example env (adjust to your stack)
FEATURE_SHOW_SAVINGS_AMOUNT=false
FEATURE_SHOW_RECOMMENDATIONS=false
FEATURE_DISCREPANCY_ALERTS=false
FEATURE_EXPORT_INCLUDE_SAVINGS_COLUMN=false
FEATURE_NEUTRAL_DATA_ONLY=true
```

Gate UI components and API response fields on these flags so turning them ON later (e.g. after insurance) is explicit and auditable.

---

## 5. Summary

| Area | Safeguard |
|------|------------|
| **DB** | Source tracking (source_id, source_type, ingested_at, optional data_sources table) |
| **API** | Fact-only responses; no recommendation/savings/alert fields; optional disclaimer in payload |
| **Webhooks** | Neutral events and payloads; no "discrepancy" or "overcharge" framing |
| **Feature flags** | Disable savings amount, recommendations, discrepancy alerts, savings column in export; enforce neutral-data mode |

These support a launch stance: "We aggregate and show market data; we do not advise or calculate what you should do." Have a UK solicitor review your final Terms and positioning alongside this document.

---

*Not legal advice. Use with CHECKLIST-UK.md and RED-FLAG-AUDIT.md.*
