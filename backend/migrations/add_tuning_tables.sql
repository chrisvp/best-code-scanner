-- Migration: Add prompt tuning tables
-- Date: 2025-12-10
-- Description: Creates tables for prompt tuning system - standalone utility for testing verification prompts

-- Prompt templates with placeholder support
CREATE TABLE IF NOT EXISTS tuning_prompt_templates (
    id INTEGER PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    description TEXT,
    template TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tuning_prompts_name ON tuning_prompt_templates(name);

-- Test cases with ground truth verdicts
CREATE TABLE IF NOT EXISTS tuning_test_cases (
    id INTEGER PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    verdict VARCHAR NOT NULL,
    issue TEXT NOT NULL,
    file VARCHAR NOT NULL,
    code TEXT NOT NULL,
    claim TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tuning_cases_name ON tuning_test_cases(name);
CREATE INDEX IF NOT EXISTS idx_tuning_cases_verdict ON tuning_test_cases(verdict);

-- Test run metadata
CREATE TABLE IF NOT EXISTS tuning_runs (
    id INTEGER PRIMARY KEY,
    name VARCHAR,
    description TEXT,
    model_ids JSON NOT NULL,
    prompt_ids JSON NOT NULL,
    test_case_ids JSON NOT NULL,
    concurrency INTEGER DEFAULT 4,
    status VARCHAR DEFAULT 'running',
    total_tests INTEGER DEFAULT 0,
    completed_tests INTEGER DEFAULT 0,
    total_duration_ms REAL,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tuning_runs_status ON tuning_runs(status);

-- Individual test results
CREATE TABLE IF NOT EXISTS tuning_results (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES tuning_runs(id),
    model_id INTEGER NOT NULL REFERENCES model_configs(id),
    model_name VARCHAR NOT NULL,
    prompt_id INTEGER NOT NULL REFERENCES tuning_prompt_templates(id),
    test_case_id INTEGER NOT NULL REFERENCES tuning_test_cases(id),
    full_prompt TEXT NOT NULL,
    raw_response TEXT,
    predicted_vote VARCHAR,
    confidence INTEGER,
    reasoning TEXT,
    correct BOOLEAN DEFAULT 0,
    parse_success BOOLEAN DEFAULT 1,
    parse_error TEXT,
    duration_ms REAL,
    tokens_in INTEGER,
    tokens_out INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tuning_results_run ON tuning_results(run_id);
CREATE INDEX IF NOT EXISTS idx_tuning_results_model ON tuning_results(model_id);
CREATE INDEX IF NOT EXISTS idx_tuning_results_prompt ON tuning_results(prompt_id);
CREATE INDEX IF NOT EXISTS idx_tuning_results_case ON tuning_results(test_case_id);
CREATE INDEX IF NOT EXISTS idx_tuning_results_correct ON tuning_results(correct);
