"""
Anonymization pipeline for compliance. Applied to stored findings before export or API response.
"""

from auditor.config import COMPLIANCE_FLAGS


def anonymize_finding(finding: dict) -> dict:
    if not COMPLIANCE_FLAGS.get("anonymize_sources"):
        return finding
    out = dict(finding)
    for key in ("source_url", "profile_url", "author_id", "post_id", "external_id"):
        if key in out and out[key]:
            out[key] = "[redacted]"
    if "sources" in out and isinstance(out["sources"], list):
        out["sources"] = [{"type": s.get("type"), "count": s.get("count")} if isinstance(s, dict) else s for s in out["sources"]]
    return out


def anonymize_findings_list(findings: list[dict]) -> list[dict]:
    return [anonymize_finding(f) for f in findings]
