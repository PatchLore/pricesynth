-- Legal compliance: purge social media and review-site data.
-- Run after removing G2 (Agent 3), Twitter/X (Agent 7), LinkedIn (Agent 8).
-- BREAKING: Data from these sources is permanently deleted.

-- If findings are in a single table with source_type:
-- DELETE FROM findings WHERE source_type IN ('g2_review', 'twitter_x', 'linkedin', 'reddit', 'forum');

-- If findings are in an audit_results or agent_outputs table:
-- DELETE FROM agent_outputs WHERE agent_id IN (3, 7, 8);
-- DELETE FROM findings WHERE source_type IN ('g2', 'twitter', 'linkedin', 'reddit', 'forum', 'g2_review', 'twitter_x');

-- Example schema-agnostic purge (adjust table/column names to your schema):
-- UPDATE findings SET payload = jsonb_set(payload - 'g2' - 'twitter' - 'linkedin', '{purged}', 'true') WHERE ...;

-- Add compliance flags table if not exists (for feature flags):
CREATE TABLE IF NOT EXISTS compliance_flags (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO compliance_flags (key, value) VALUES
    ('purge_social_data', 'true'),
    ('anonymize_sources', 'true'),
    ('audit_trail_compliance', 'true')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();

-- Optional: add source_type to findings and backfill for safe sources only:
-- ALTER TABLE findings ADD COLUMN IF NOT EXISTS source_type TEXT;
-- UPDATE findings SET source_type = 'official_page' WHERE agent_id = 1;
-- UPDATE findings SET source_type = 'wayback' WHERE agent_id = 4;
-- UPDATE findings SET source_type = 'partner_program' WHERE agent_id = 5;
-- UPDATE findings SET source_type = 'public_record' WHERE agent_id = 9;
