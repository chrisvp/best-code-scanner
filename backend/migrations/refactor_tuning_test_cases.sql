-- Migration to align tuning_test_cases with real verification workflow
-- Run: sqlite3 backend/data/scans.db < backend/migrations/refactor_tuning_test_cases.sql

-- Step 1: Add new columns to match draft_findings structure
ALTER TABLE tuning_test_cases ADD COLUMN title VARCHAR;
ALTER TABLE tuning_test_cases ADD COLUMN vulnerability_type VARCHAR;
ALTER TABLE tuning_test_cases ADD COLUMN severity VARCHAR;
ALTER TABLE tuning_test_cases ADD COLUMN line_number INTEGER;
ALTER TABLE tuning_test_cases ADD COLUMN snippet TEXT;
ALTER TABLE tuning_test_cases ADD COLUMN reason TEXT;
ALTER TABLE tuning_test_cases ADD COLUMN file_path VARCHAR;
ALTER TABLE tuning_test_cases ADD COLUMN language VARCHAR;

-- Step 2: Migrate existing data to new columns (preserve backwards compat)
UPDATE tuning_test_cases
SET
    title = issue,
    vulnerability_type = issue,
    snippet = code,
    reason = claim,
    file_path = file
WHERE draft_finding_id IS NULL;

-- Step 3: Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_ttc_draft_finding ON tuning_test_cases(draft_finding_id);
CREATE INDEX IF NOT EXISTS idx_ttc_verdict ON tuning_test_cases(verdict);
