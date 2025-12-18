-- Enhance tuning_test_cases with full context and provenance
-- Migration: enhance_tuning_test_cases
-- Date: 2025-12-18

-- Full context fields (what verifiers see during scans)
ALTER TABLE tuning_test_cases ADD COLUMN full_code_chunk TEXT;
ALTER TABLE tuning_test_cases ADD COLUMN chunk_id INTEGER REFERENCES scan_file_chunks(id);
ALTER TABLE tuning_test_cases ADD COLUMN surrounding_lines INTEGER DEFAULT 10;

-- Source scan metadata (provenance tracking)
ALTER TABLE tuning_test_cases ADD COLUMN source_scan_id INTEGER REFERENCES scans(id);
ALTER TABLE tuning_test_cases ADD COLUMN source_scan_name VARCHAR;

-- Historical verification data
ALTER TABLE tuning_test_cases ADD COLUMN verification_votes_json JSON;
ALTER TABLE tuning_test_cases ADD COLUMN consensus_vote VARCHAR;
ALTER TABLE tuning_test_cases ADD COLUMN vote_confidence_avg REAL;

-- Categorization and filtering
ALTER TABLE tuning_test_cases ADD COLUMN cwe_type VARCHAR;
ALTER TABLE tuning_test_cases ADD COLUMN is_synthetic BOOLEAN DEFAULT 0;
ALTER TABLE tuning_test_cases ADD COLUMN difficulty_score REAL;
ALTER TABLE tuning_test_cases ADD COLUMN tags JSON;

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_tuning_test_cases_source_scan ON tuning_test_cases(source_scan_id);
CREATE INDEX IF NOT EXISTS idx_tuning_test_cases_cwe_type ON tuning_test_cases(cwe_type);
CREATE INDEX IF NOT EXISTS idx_tuning_test_cases_is_synthetic ON tuning_test_cases(is_synthetic);

-- Add versioning to prompts for A/B testing
ALTER TABLE tuning_prompt_templates ADD COLUMN version INTEGER DEFAULT 1;
ALTER TABLE tuning_prompt_templates ADD COLUMN parent_id INTEGER REFERENCES tuning_prompt_templates(id);
ALTER TABLE tuning_prompt_templates ADD COLUMN is_active BOOLEAN DEFAULT 1;

-- Add benchmark metadata to runs
ALTER TABLE tuning_runs ADD COLUMN benchmark_type VARCHAR DEFAULT 'accuracy';
ALTER TABLE tuning_runs ADD COLUMN baseline_run_id INTEGER REFERENCES tuning_runs(id);
ALTER TABLE tuning_runs ADD COLUMN notes TEXT;

-- Add per-CWE and statistical metrics to results
ALTER TABLE tuning_results ADD COLUMN cwe_type VARCHAR;
ALTER TABLE tuning_results ADD COLUMN false_positive_type VARCHAR; -- 'Type I', 'Type II', NULL

COMMIT;
