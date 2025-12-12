-- Migration: Add profile verifiers, verification votes, and global settings
-- Date: 2025-12-02
-- Description: Restructures scan profiles to have configurable verifiers and enricher,
--              adds vote logging table, and creates global settings for cleanup model

-- ============================================================================
-- 1. Add new columns to scan_profiles
-- ============================================================================

-- Enricher configuration
ALTER TABLE scan_profiles ADD COLUMN enricher_model_id INTEGER REFERENCES model_configs(id);
ALTER TABLE scan_profiles ADD COLUMN enricher_prompt_template TEXT;

-- Verification settings
ALTER TABLE scan_profiles ADD COLUMN verification_threshold INTEGER DEFAULT 2;
ALTER TABLE scan_profiles ADD COLUMN require_unanimous_reject BOOLEAN DEFAULT 0;


-- ============================================================================
-- 2. Create profile_verifiers table
-- ============================================================================

CREATE TABLE IF NOT EXISTS profile_verifiers (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER REFERENCES scan_profiles(id),
    name VARCHAR,
    description TEXT,
    model_id INTEGER NOT NULL REFERENCES model_configs(id),
    prompt_template TEXT,
    vote_weight FLOAT DEFAULT 1.0,
    min_confidence INTEGER DEFAULT 0,
    run_order INTEGER DEFAULT 1,
    enabled BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_profile_verifiers_profile_id ON profile_verifiers(profile_id);


-- ============================================================================
-- 3. Create verification_votes table (for logging individual votes)
-- ============================================================================

CREATE TABLE IF NOT EXISTS verification_votes (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    draft_finding_id INTEGER REFERENCES draft_findings(id),
    model_name VARCHAR,
    verifier_id INTEGER REFERENCES profile_verifiers(id),
    decision VARCHAR,  -- VERIFY, WEAKNESS, REJECT, ABSTAIN
    confidence INTEGER,
    reasoning TEXT,
    attack_scenario TEXT,
    raw_response TEXT,
    parse_success BOOLEAN DEFAULT 1,
    format_detected VARCHAR,
    vote_weight FLOAT DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_verification_votes_scan_id ON verification_votes(scan_id);
CREATE INDEX IF NOT EXISTS ix_verification_votes_draft_finding_id ON verification_votes(draft_finding_id);
CREATE INDEX IF NOT EXISTS ix_verification_votes_model_name ON verification_votes(model_name);


-- ============================================================================
-- 4. Create global_settings table
-- ============================================================================

CREATE TABLE IF NOT EXISTS global_settings (
    id INTEGER PRIMARY KEY,
    key VARCHAR UNIQUE NOT NULL,
    value TEXT,
    value_type VARCHAR DEFAULT 'string',  -- string, int, bool, json
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_global_settings_key ON global_settings(key);

-- Insert default global settings
INSERT OR IGNORE INTO global_settings (key, value, value_type, description) VALUES
    ('cleanup_model_id', NULL, 'int', 'Model ID for cleaning up malformed LLM responses'),
    ('cleanup_prompt_template', 'The following LLM response is malformed and needs to be reformatted. Please extract the relevant information and output it in the correct format.

Original response:
{response}

Expected format:
{format_template}

Output only the corrected response, nothing else.', 'string', 'Prompt template for cleanup model');


-- ============================================================================
-- 5. Migrate existing verifier configurations to profile_verifiers
-- ============================================================================

-- For each existing profile, create profile_verifiers from models marked as is_verifier
-- This preserves backward compatibility

INSERT INTO profile_verifiers (profile_id, name, model_id, prompt_template, enabled, run_order)
SELECT
    sp.id as profile_id,
    mc.name || ' Verifier' as name,
    mc.id as model_id,
    mc.verification_prompt_template as prompt_template,
    1 as enabled,
    ROW_NUMBER() OVER (PARTITION BY sp.id ORDER BY mc.id) as run_order
FROM scan_profiles sp
CROSS JOIN model_configs mc
WHERE mc.is_verifier = 1
  AND NOT EXISTS (
      SELECT 1 FROM profile_verifiers pv
      WHERE pv.profile_id = sp.id AND pv.model_id = mc.id
  );


-- ============================================================================
-- 6. Set enricher for existing profiles (use first analyzer model as fallback)
-- ============================================================================

-- Only set if not already set
UPDATE scan_profiles
SET enricher_model_id = (
    SELECT model_id FROM profile_analyzers
    WHERE profile_id = scan_profiles.id
    ORDER BY run_order LIMIT 1
)
WHERE enricher_model_id IS NULL
  AND EXISTS (SELECT 1 FROM profile_analyzers WHERE profile_id = scan_profiles.id);


-- ============================================================================
-- Done!
-- ============================================================================
