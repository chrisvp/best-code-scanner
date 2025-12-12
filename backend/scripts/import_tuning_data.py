#!/usr/bin/env python3
"""
Import prompt tuning test data from test_library/ into the database.
Rewritten to use pure sqlite3 to avoid environment dependency issues.
"""

import json
import os
import sys
import sqlite3
from pathlib import Path

# DB Path
DB_PATH = Path(__file__).parent.parent / "data" / "scans.db"

def run_migration(conn):
    """Run the SQL migration to create tuning tables"""
    migration_file = Path(__file__).parent.parent / "migrations" / "add_tuning_tables.sql"

    if not migration_file.exists():
        print(f"Migration file not found: {migration_file}")
        return False

    print(f"Running migration: {migration_file}")

    with open(migration_file, 'r') as f:
        migration_sql = f.read()

    cursor = conn.cursor()
    statements = [s.strip() for s in migration_sql.split(';') if s.strip()]
    for statement in statements:
        try:
            cursor.execute(statement)
        except sqlite3.OperationalError as e:
            if "already exists" not in str(e):
                print(f"Warning: {e}")

    conn.commit()
    return True

def import_prompts(conn):
    """Import prompt templates from test_library/prompts.json"""
    prompts_file = Path(__file__).parent.parent / "test_library" / "prompts.json"

    if not prompts_file.exists():
        print(f"Prompts file not found: {prompts_file}")
        return 0

    with open(prompts_file, 'r') as f:
        prompts_data = json.load(f)

    cursor = conn.cursor()
    count = 0
    updated = 0
    
    for name, template in prompts_data.items():
        cursor.execute("SELECT id FROM tuning_prompt_templates WHERE name = ?", (name,))
        existing = cursor.fetchone()

        if existing:
            # Update existing
            cursor.execute(
                "UPDATE tuning_prompt_templates SET template = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                (template, name)
            )
            updated += 1
        else:
            # Create new
            cursor.execute(
                "INSERT INTO tuning_prompt_templates (name, description, template) VALUES (?, ?, ?)",
                (name, f"Imported from test_library (format variant {name})", template)
            )
            count += 1
            print(f"Imported prompt: {name}")

    conn.commit()
    print(f"Prompts: {count} created, {updated} updated")
    return count

def import_test_cases(conn):
    """Import test cases from test_library/findings.json"""
    findings_file = Path(__file__).parent.parent / "test_library" / "findings.json"

    if not findings_file.exists():
        print(f"Findings file not found: {findings_file}")
        return 0

    with open(findings_file, 'r') as f:
        findings_data = json.load(f)

    cursor = conn.cursor()
    count = 0
    
    for name, data in findings_data.items():
        cursor.execute("SELECT id FROM tuning_test_cases WHERE name = ?", (name,))
        existing = cursor.fetchone()

        if existing:
            continue

        cursor.execute(
            """INSERT INTO tuning_test_cases 
               (name, verdict, issue, file, code, claim) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, data['verdict'], data['issue'], data['file'], data['code'], data['claim'])
        )
        count += 1
        print(f"Imported test case: {name}")

    conn.commit()
    return count

def main():
    print(f"Using database: {DB_PATH}")
    
    conn = sqlite3.connect(str(DB_PATH))
    
    try:
        run_migration(conn)
        import_prompts(conn)
        import_test_cases(conn)
        print("Import completed successfully.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()