#!/usr/bin/env python3
"""Fix database schema - add missing columns to existing tables"""
import sqlite3

db_path = 'backend/scans.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

migrations = [
    # scans table
    ("ALTER TABLE scans ADD COLUMN current_phase VARCHAR DEFAULT 'queued'", "scans.current_phase"),

    # findings table
    ("ALTER TABLE findings ADD COLUMN status VARCHAR", "findings.status"),
    ("ALTER TABLE findings ADD COLUMN draft_id INTEGER", "findings.draft_id"),
    ("ALTER TABLE findings ADD COLUMN status_changed_at DATETIME", "findings.status_changed_at"),
    ("ALTER TABLE findings ADD COLUMN status_changed_by_id INTEGER", "findings.status_changed_by_id"),

    # model_configs table
    ("ALTER TABLE model_configs ADD COLUMN tool_call_format VARCHAR", "model_configs.tool_call_format"),
    ("ALTER TABLE model_configs ADD COLUMN response_format VARCHAR", "model_configs.response_format"),
    ("ALTER TABLE model_configs ADD COLUMN max_context_length INTEGER", "model_configs.max_context_length"),

    # draft_findings table
    ("ALTER TABLE draft_findings ADD COLUMN file_path VARCHAR", "draft_findings.file_path"),
    ("ALTER TABLE draft_findings ADD COLUMN analyzer_id INTEGER", "draft_findings.analyzer_id"),
    ("ALTER TABLE draft_findings ADD COLUMN analyzer_name VARCHAR", "draft_findings.analyzer_name"),

    # scan_profiles table
    ("ALTER TABLE scan_profiles ADD COLUMN first_phase_method VARCHAR DEFAULT 'llm'", "scan_profiles.first_phase_method"),
    ("ALTER TABLE scan_profiles ADD COLUMN joern_chunk_strategy VARCHAR DEFAULT 'directory'", "scan_profiles.joern_chunk_strategy"),
    ("ALTER TABLE scan_profiles ADD COLUMN joern_max_files_per_cpg INTEGER DEFAULT 100", "scan_profiles.joern_max_files_per_cpg"),
    ("ALTER TABLE scan_profiles ADD COLUMN joern_query_set VARCHAR DEFAULT 'default'", "scan_profiles.joern_query_set"),
    ("ALTER TABLE scan_profiles ADD COLUMN verification_threshold INTEGER DEFAULT 1", "scan_profiles.verification_threshold"),
    ("ALTER TABLE scan_profiles ADD COLUMN require_unanimous_reject BOOLEAN DEFAULT 0", "scan_profiles.require_unanimous_reject"),
    ("ALTER TABLE scan_profiles ADD COLUMN agentic_verifier_mode VARCHAR", "scan_profiles.agentic_verifier_mode"),
    ("ALTER TABLE scan_profiles ADD COLUMN agentic_verifier_model_id INTEGER", "scan_profiles.agentic_verifier_model_id"),
    ("ALTER TABLE scan_profiles ADD COLUMN agentic_verifier_max_steps INTEGER DEFAULT 8", "scan_profiles.agentic_verifier_max_steps"),
    ("ALTER TABLE scan_profiles ADD COLUMN enricher_model_id INTEGER", "scan_profiles.enricher_model_id"),
    ("ALTER TABLE scan_profiles ADD COLUMN enricher_prompt_template TEXT", "scan_profiles.enricher_prompt_template"),

    # profile_analyzers table
    ("ALTER TABLE profile_analyzers ADD COLUMN output_mode VARCHAR DEFAULT 'markers'", "profile_analyzers.output_mode"),
    ("ALTER TABLE profile_analyzers ADD COLUMN json_schema TEXT", "profile_analyzers.json_schema"),

    # scan_configs table
    ("ALTER TABLE scan_configs ADD COLUMN source_scan_id INTEGER", "scan_configs.source_scan_id"),

    # llm_request_logs table
    ("ALTER TABLE llm_request_logs ADD COLUMN status VARCHAR", "llm_request_logs.status"),

    # tuning_test_cases table
    ("ALTER TABLE tuning_test_cases ADD COLUMN title VARCHAR", "tuning_test_cases.title"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN vulnerability_type VARCHAR", "tuning_test_cases.vulnerability_type"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN severity VARCHAR", "tuning_test_cases.severity"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN line_number INTEGER", "tuning_test_cases.line_number"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN snippet TEXT", "tuning_test_cases.snippet"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN reason TEXT", "tuning_test_cases.reason"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN file_path VARCHAR", "tuning_test_cases.file_path"),
    ("ALTER TABLE tuning_test_cases ADD COLUMN language VARCHAR", "tuning_test_cases.language"),
]

print("Applying schema fixes...")
for sql, desc in migrations:
    try:
        cursor.execute(sql)
        print(f"  ✅ Added {desc}")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e).lower():
            print(f"  ⏭️  {desc} (already exists)")
        else:
            print(f"  ❌ {desc}: {e}")

conn.commit()
conn.close()
print("\n✅ Schema migration complete!")
