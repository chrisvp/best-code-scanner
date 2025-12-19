-- Drop old backwards-compat fields from tuning_test_cases
-- Run this after server restart to avoid lock

-- SQLite doesn't support DROP COLUMN directly, need to recreate table
-- But since we're using SQLAlchemy, just removing from model will work
-- If you need to actually drop the columns:

-- 1. Create new table without old columns
CREATE TABLE tuning_test_cases_new (
    id INTEGER PRIMARY KEY,
    name VARCHAR UNIQUE NOT NULL,
    verdict VARCHAR NOT NULL,
    draft_finding_id INTEGER REFERENCES draft_findings(id),

    title VARCHAR,
    vulnerability_type VARCHAR,
    severity VARCHAR,
    line_number INTEGER,
    snippet TEXT,
    reason TEXT,
    file_path VARCHAR,
    language VARCHAR,

    full_code_chunk TEXT,
    chunk_id INTEGER REFERENCES scan_file_chunks(id),
    surrounding_lines INTEGER DEFAULT 10,

    source_scan_id INTEGER REFERENCES scans(id),
    source_scan_name VARCHAR,

    verification_votes_json JSON,
    consensus_vote VARCHAR,
    vote_confidence_avg REAL,

    cwe_type VARCHAR,
    is_synthetic BOOLEAN DEFAULT 0,
    difficulty_score REAL,

    tags JSON,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- 2. Copy data
INSERT INTO tuning_test_cases_new
SELECT
    id, name, verdict, draft_finding_id,
    title, vulnerability_type, severity, line_number, snippet, reason, file_path, language,
    full_code_chunk, chunk_id, surrounding_lines,
    source_scan_id, source_scan_name,
    verification_votes_json, consensus_vote, vote_confidence_avg,
    cwe_type, is_synthetic, difficulty_score,
    tags,
    created_at, updated_at
FROM tuning_test_cases;

-- 3. Drop old table and rename
DROP TABLE tuning_test_cases;
ALTER TABLE tuning_test_cases_new RENAME TO tuning_test_cases;

-- 4. Recreate indexes
CREATE UNIQUE INDEX idx_tuning_test_cases_name ON tuning_test_cases(name);
CREATE INDEX idx_tuning_test_cases_verdict ON tuning_test_cases(verdict);
CREATE INDEX idx_tuning_test_cases_draft_finding_id ON tuning_test_cases(draft_finding_id);
CREATE INDEX idx_tuning_test_cases_source_scan_id ON tuning_test_cases(source_scan_id);
CREATE INDEX idx_tuning_test_cases_cwe_type ON tuning_test_cases(cwe_type);
CREATE INDEX idx_tuning_test_cases_is_synthetic ON tuning_test_cases(is_synthetic);
