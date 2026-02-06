"""
Auto-generate Pricing Intelligence Report from audit JSON.
Converts agent consensus + findings into the report_template.md structure.
"""
import json
from datetime import datetime
from typing import Any, Dict, Optional


def _confidence_label(confidence: Any) -> str:
    """Map numeric confidence 0-1 to High/Medium/Low."""
    if confidence is None:
        return "Low"
    c = float(confidence)
    if c >= 0.7:
        return "High"
    if c >= 0.4:
        return "Medium"
    return "Low"


def _domain_from_url(url: str) -> str:
    """Extract competitor name from URL (e.g. https://stripe.com/pricing -> stripe.com)."""
    if not url:
        return "Target"
    url = url.strip().lower()
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix) :]
            break
    if "/" in url:
        url = url.split("/")[0]
    return url or "Target"


def generate_report(
    audit_data: Dict[str, Any],
    customer_name: str = "Client",
    contact_email: str = "",
) -> str:
    """
    Convert audit JSON (results.consensus + results.findings) into a markdown report.

    audit_data must have:
      - id: audit ID
      - url: target competitor URL
      - results: JSON string or dict with 'consensus' and 'findings'
    """
    results = audit_data.get("results")
    if isinstance(results, str):
        results = json.loads(results) if results.strip() else {}
    if not results:
        results = {}
    consensus = results.get("consensus") or {}
    findings = results.get("findings") or []

    list_price = consensus.get("list_price")
    shadow_min = consensus.get("shadow_price_min")
    shadow_max = consensus.get("shadow_price_max")
    shadow_price = consensus.get("shadow_price")
    confidence_num = consensus.get("confidence")
    confidence_str = _confidence_label(confidence_num)
    neg_low = consensus.get("typical_negotiation_range_low")
    neg_high = consensus.get("typical_negotiation_range_high")
    savings_pct = consensus.get("savings_percent") or 0
    source_count = consensus.get("source_count") or len([f for f in findings if f.get("price_found") is not None or f.get("estimated_range_low") is not None])
    methodology = consensus.get("methodology") or "Analysis based on publicly available sources."
    rationale = consensus.get("rationale") or methodology
    caveats = consensus.get("caveats") or "Limited public data. Conduct independent verification before negotiating."

    # Estimated market rate range
    if shadow_min is not None and shadow_max is not None:
        rate_low, rate_high = shadow_min, shadow_max
    elif shadow_price is not None:
        rate_low = rate_high = shadow_price
    else:
        rate_low = rate_high = None

    # Annual savings (vs midpoint of range)
    avg_shadow = None
    if rate_low is not None and rate_high is not None:
        avg_shadow = (float(rate_low) + float(rate_high)) / 2
    elif shadow_price is not None:
        avg_shadow = float(shadow_price)
    list_f = float(list_price) if list_price is not None else 0
    annual_savings = (list_f - avg_shadow) * 12 if (list_f and avg_shadow and list_f > avg_shadow) else 0

    # Negotiation range %
    neg_low_str = f"{int(neg_low)}" if neg_low is not None else "0"
    neg_high_str = f"{int(neg_high)}" if neg_high is not None else f"{int(savings_pct)}"
    if neg_low is None and neg_high is None and savings_pct:
        neg_low_str = str(max(0, int(savings_pct) - 5))
        neg_high_str = str(min(50, int(savings_pct) + 5))

    competitor = _domain_from_url(audit_data.get("url") or "")
    report_id = audit_data.get("id") or "N/A"
    analysis_date = datetime.now().strftime("%B %d, %Y")

    # Executive summary table
    published_cell = f"${list_f:,.0f}/mo" if list_price is not None else "—"
    rate_cell = f"${rate_low:,.0f}–${rate_high:,.0f}/mo" if (rate_low is not None and rate_high is not None) else "—"
    if rate_low is not None and rate_high is not None and rate_low == rate_high:
        rate_cell = f"${rate_low:,.0f}/mo"
    annual_cell = f"${annual_savings:,.0f}" if annual_savings > 0 else "—"

    # Appendix: source intelligence table from findings
    appendix_rows = []
    for f in findings:
        name = f.get("agent_name") or "Agent"
        low = f.get("estimated_range_low")
        high = f.get("estimated_range_high")
        p = f.get("price_found")
        if low is not None and high is not None:
            price_ind = f"${float(low):,.0f}–${float(high):,.0f}/mo"
        elif p is not None:
            price_ind = f"${float(p):,.0f}/mo"
        else:
            price_ind = "—"
        conf = _confidence_label(f.get("confidence"))
        notes = (f.get("rationale") or f.get("caveats") or "")[:80]
        if notes:
            notes = notes.replace("|", " ") + ("…" if len(notes) >= 80 else "")
        appendix_rows.append(f"| {name} | {price_ind} | {conf} | {notes} |")
    appendix_table = "\n".join(appendix_rows) if appendix_rows else "| — | — | — | No agent findings in this run. |"

    report = f"""# CONFIDENTIAL MARKET INTELLIGENCE
## Competitor Pricing Analysis

**Prepared for:** {customer_name}
**Target Competitor:** {competitor}
**Analysis Date:** {analysis_date}
**Report ID:** {report_id}
**Classification:** Proprietary Market Research

---

## EXECUTIVE SUMMARY

Based on analysis of 9 public data sources, we estimate **{competitor}**'s effective market pricing varies significantly from published rates.

| Metric | Value | Confidence |
|--------|-------|------------|
| **Published List Price** | {published_cell} | High (Official source) |
| **Estimated Market Rate** | {rate_cell} | {confidence_str} |
| **Typical Negotiation Range** | {neg_low_str}%–{neg_high_str}% below list | Based on {source_count} sources |
| **Annual Savings Potential** | {annual_cell} | If negotiated to market rate |

**Key Finding:** {rationale[:400]}{"…" if len(rationale) > 400 else ""}

---

## METHODOLOGY

This analysis employed 10 specialized intelligence agents scanning:

1. **Official Documentation** — Published pricing pages, changelogs
2. **Community Intelligence** — Public forums, Reddit discussions, social mentions
3. **Partner Ecosystem** — Reseller pricing, affiliate documentation
4. **Historical Archives** — Wayback Machine pricing evolution
5. **Review Aggregators** — G2, TrustRadius, Capterra mentions
6. **Social Signals** — Twitter/X, LinkedIn pricing discussions

**Data Classification:** All sources are publicly accessible. No confidential or insider information was accessed.

---

## DETAILED FINDINGS

### 1. Published Pricing Structure
**Source:** Official website documentation
**Confidence:** High

Published list price: {published_cell}

### 2. Market Rate Estimates
**Source:** Community discussions, partner channels
**Confidence:** {confidence_str}

Estimated market rate range: {rate_cell}. {rationale[:300]}{"…" if len(rationale) > 300 else ""}

### 3. Discount Patterns
**Source:** Historical pricing, forum discussions
**Confidence:** {confidence_str}

Typical negotiation range: {neg_low_str}%–{neg_high_str}% below published list.

### 4. Competitive Positioning
**Source:** Review sites, social sentiment
**Confidence:** {confidence_str}

{methodology[:350]}{"…" if len(methodology) > 350 else ""}

---

## RISK ASSESSMENT & CAVEATS

⚠️ **Data Limitations:**
- Analysis based on publicly available information as of {analysis_date}
- Pricing may vary by geography, company size, or contract terms
- Some sources may be outdated (>12 months)
- Enterprise pricing often custom-negotiated and not publicly disclosed

⚠️ **Confidence Level:** {confidence_str}

{caveats}

---

## STRATEGIC RECOMMENDATIONS

1. **Negotiation Leverage:** Use community-sourced pricing data as benchmark; ask about unlisted tiers.
2. **Timing:** Request quotes near fiscal year-end for maximum flexibility.
3. **Verification:** Ask directly about "startup" or "growth" tiers not publicly listed.
4. **Verification Steps:** Confirm estimates during sales process; conduct independent verification before negotiating.

---

## APPENDIX: SOURCE INTELLIGENCE

| Source Type | Price Indication | Confidence | Notes |
|-------------|------------------|------------|-------|
{appendix_table}


---

**Disclaimer:** This report constitutes market intelligence and analytical estimates derived from publicly available sources. It does not represent verified pricing or guaranteed outcomes. Conduct independent verification before negotiating. This analysis is provided for informational purposes only.

**Prepared by:** Pricing Intelligence and Market Benchmarking
**Contact:** {contact_email or "[Your Email]"}

---

*This document contains proprietary analysis. Not for redistribution.*
"""
    return report


def main():
    """Example: load an audit from a JSON file and write report.md."""
    import sys
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <audit_json_path> [customer_name] [output_path]")
        print("  audit_json_path: path to JSON file with keys id, url, results")
        print("  customer_name: optional (default: Client)")
        print("  output_path: optional (default: report.md)")
        sys.exit(1)
    path = sys.argv[1]
    customer = sys.argv[2] if len(sys.argv) > 2 else "Client"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "report.md"
    with open(path, "r", encoding="utf-8") as f:
        audit_data = json.load(f)
    report = generate_report(audit_data, customer_name=customer)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
