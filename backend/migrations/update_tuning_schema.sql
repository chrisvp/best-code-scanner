-- Migration: Update tuning schema to reference draft_findings
-- Date: 2025-12-10
-- Description: Add draft_finding_id reference, make copied fields optional

-- Add draft_finding_id column to link to actual findings
ALTER TABLE tuning_test_cases ADD COLUMN draft_finding_id INTEGER REFERENCES draft_findings(id);

-- Make the copied fields nullable since we'll pull from draft_findings at runtime
-- (SQLite doesn't support modifying column constraints, so we'll handle this at application level)

CREATE INDEX IF NOT EXISTS idx_tuning_cases_draft_finding ON tuning_test_cases(draft_finding_id);
