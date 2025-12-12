#!/usr/bin/env python3
"""
Migrate tuning_test_cases schema to match real verification workflow.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.core.database import get_db

def run_migration():
    """Run schema migration for tuning_test_cases"""
    db = next(get_db())

    try:
        print("Starting tuning_test_cases schema migration...")

        # Check if columns already exist
        result = db.execute(text("PRAGMA table_info(tuning_test_cases)")).fetchall()
        existing_columns = {row[1] for row in result}

        migrations = [
            ("title", "ALTER TABLE tuning_test_cases ADD COLUMN title VARCHAR"),
            ("vulnerability_type", "ALTER TABLE tuning_test_cases ADD COLUMN vulnerability_type VARCHAR"),
            ("severity", "ALTER TABLE tuning_test_cases ADD COLUMN severity VARCHAR"),
            ("line_number", "ALTER TABLE tuning_test_cases ADD COLUMN line_number INTEGER"),
            ("snippet", "ALTER TABLE tuning_test_cases ADD COLUMN snippet TEXT"),
            ("reason", "ALTER TABLE tuning_test_cases ADD COLUMN reason TEXT"),
            ("file_path", "ALTER TABLE tuning_test_cases ADD COLUMN file_path VARCHAR"),
            ("language", "ALTER TABLE tuning_test_cases ADD COLUMN language VARCHAR"),
        ]

        for col_name, sql in migrations:
            if col_name not in existing_columns:
                print(f"  Adding column: {col_name}")
                db.execute(text(sql))
                db.commit()
            else:
                print(f"  Column already exists: {col_name}")

        # Migrate existing data
        print("\nMigrating existing data...")
        db.execute(text("""
            UPDATE tuning_test_cases
            SET
                title = issue,
                vulnerability_type = issue,
                snippet = code,
                reason = claim,
                file_path = file
            WHERE title IS NULL
        """))
        db.commit()

        # Create indexes
        print("\nCreating indexes...")
        try:
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_ttc_draft_finding ON tuning_test_cases(draft_finding_id)"))
            db.commit()
        except:
            pass

        try:
            db.execute(text("CREATE INDEX IF NOT EXISTS idx_ttc_verdict ON tuning_test_cases(verdict)"))
            db.commit()
        except:
            pass

        print("\nMigration complete!")
        print(f"Total test cases: {db.execute(text('SELECT COUNT(*) FROM tuning_test_cases')).scalar()}")

    except Exception as e:
        print(f"Error during migration: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    run_migration()
