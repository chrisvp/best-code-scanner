#!/usr/bin/env python3
"""
Script to extract all 20 creative prompt templates from CREATIVE_PROMPTS.md
and insert them into the database with proper template variable validation.

The markdown uses finding_* variables which the tuning system supports directly,
so we don't need to rename them.
"""

import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple

def read_markdown_file(file_path: str) -> str:
    """Read the markdown file containing creative prompts."""
    with open(file_path, 'r') as f:
        return f.read()

def extract_templates(content: str) -> List[Dict[str, str]]:
    """Extract all templates from the markdown content."""
    templates = []

    # Split by "## " to get each template section
    sections = re.split(r'^## \d+\. ', content, flags=re.MULTILINE)[1:]

    for section in sections:
        # Extract template name (first line before newline)
        name_match = re.match(r'^([^\n]+)', section)
        if not name_match:
            continue

        template_name = name_match.group(1).strip()

        # Extract template content from code block
        # Templates end with ``` followed by **Rationale**:
        # This avoids issues with nested code blocks
        template_match = re.search(r'\*\*Template\*\*:\s*\n```\n(.*?)\n```\s*\n\s*\*\*Rationale\*\*:', section, re.DOTALL)

        if template_match:
            template_content = template_match.group(1).strip()
            templates.append({
                'name': template_name,
                'template': template_content
            })
            print(f"✓ Extracted template: {template_name}")
        else:
            print(f"✗ Could not extract template for: {template_name}")

    return templates

def fix_template_variables(template: str) -> str:
    """
    Ensure template has required variables.

    The markdown uses finding_* variables which are valid.
    We just need to ensure we have {code_context} and {output_format}.
    """
    # Add code_context if not present (it's used as {context} in tuning)
    # The tuning system provides both 'code_context' and 'context' as aliases
    if '{code_context}' not in template and '{context}' not in template:
        # Add context section before the main prompt content
        context_section = "\nFull file context:\n{code_context}\n"
        # Insert after the code snippet section
        if 'Code context:' in template:
            parts = template.split('Reported vulnerability:')
            if len(parts) == 2:
                template = parts[0] + context_section + '\nReported vulnerability:' + parts[1]
        else:
            # Add at the beginning after file/language
            lines = template.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if 'Language:' in line:
                    insert_idx = i + 1
                    break
            if insert_idx > 0:
                lines.insert(insert_idx, context_section)
                template = '\n'.join(lines)

    # Check if output_format is present, if not add it at the end
    if '{output_format}' not in template:
        template = template.rstrip() + '\n\n{output_format}'

    return template

def validate_template(template: str, name: str) -> bool:
    """
    Validate that template has all required variables.

    The tuning system provides these variables (from _get_test_case_data):
    Primary: finding_title, finding_type, finding_severity, finding_line, finding_reason, code_snippet
    Also provides: code_context (or context), file_path, language, output_format
    """
    # Check for primary variables (either the finding_* or their aliases)
    required_checks = [
        ('{file_path}', ['{file_path}', '{file}']),
        ('{language}', ['{language}']),
        ('{code_snippet}', ['{code_snippet}', '{snippet}', '{code}']),
        ('{code_context}', ['{code_context}', '{context}']),
        ('{finding_title}', ['{finding_title}', '{title}', '{issue}']),
        ('{finding_type}', ['{finding_type}', '{vuln_type}', '{vulnerability_type}']),
        ('{finding_severity}', ['{finding_severity}', '{severity}']),
        ('{finding_line}', ['{finding_line}', '{line}', '{line_number}']),
        ('{finding_reason}', ['{finding_reason}', '{reason}', '{details}', '{claim}']),
        ('{output_format}', ['{output_format}']),
    ]

    missing = []
    for primary, alternatives in required_checks:
        found = any(alt in template for alt in alternatives)
        if not found:
            missing.append(primary)

    if missing:
        print(f"  ⚠ Template '{name}' missing variables: {missing}")
        return False

    print(f"  ✓ Template '{name}' has all required variables")
    return True

def insert_to_database(templates: List[Dict[str, str]], db_path: str):
    """Insert templates into the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tuning_prompt_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR NOT NULL UNIQUE,
            template TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    inserted = 0
    updated = 0
    failed = 0

    for template_dict in templates:
        name = template_dict['name']
        template = fix_template_variables(template_dict['template'])

        # Validate template
        if not validate_template(template, name):
            failed += 1
            continue

        try:
            # Try to insert or update
            cursor.execute("""
                INSERT INTO tuning_prompt_templates (name, template)
                VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    template = excluded.template
            """, (name, template))

            if cursor.rowcount > 0:
                if cursor.lastrowid:
                    inserted += 1
                    print(f"  ✓ Inserted: {name}")
                else:
                    updated += 1
                    print(f"  ↻ Updated: {name}")
        except sqlite3.IntegrityError:
            # Try update if insert fails (older SQLite versions)
            try:
                cursor.execute("""
                    UPDATE tuning_prompt_templates
                    SET template = ?
                    WHERE name = ?
                """, (template, name))
                if cursor.rowcount > 0:
                    updated += 1
                    print(f"  ↻ Updated: {name}")
                else:
                    cursor.execute("""
                        INSERT INTO tuning_prompt_templates (name, template)
                        VALUES (?, ?)
                    """, (name, template))
                    inserted += 1
                    print(f"  ✓ Inserted: {name}")
            except Exception as e:
                print(f"  ✗ Failed to insert/update {name}: {e}")
                failed += 1

    conn.commit()
    conn.close()

    return inserted, updated, failed

def main():
    """Main function to orchestrate the extraction and insertion."""
    print("=" * 60)
    print("CREATIVE PROMPT TEMPLATE IMPORTER")
    print("=" * 60)

    # Paths
    markdown_path = "/home/aiadmin/web-davy-code-scanner/backend/docs/CREATIVE_PROMPTS.md"
    db_path = "/home/aiadmin/web-davy-code-scanner/backend/data/scans.db"

    # Check files exist
    if not Path(markdown_path).exists():
        print(f"❌ Error: Markdown file not found: {markdown_path}")
        return 1

    if not Path(db_path).exists():
        print(f"❌ Error: Database not found: {db_path}")
        return 1

    print(f"📖 Reading from: {markdown_path}")
    content = read_markdown_file(markdown_path)

    print("\n📋 Extracting templates...")
    templates = extract_templates(content)
    print(f"\n✓ Found {len(templates)} templates")

    # List the templates found
    print("\n📝 Templates found:")
    for i, t in enumerate(templates, 1):
        print(f"  {i:2d}. {t['name']}")

    print(f"\n💾 Inserting into database: {db_path}")
    inserted, updated, failed = insert_to_database(templates, db_path)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"✅ Inserted: {inserted}")
    print(f"↻  Updated:  {updated}")
    print(f"❌ Failed:   {failed}")
    print(f"📊 Total:    {inserted + updated + failed}/{len(templates)}")

    # Verify in database
    print("\n🔍 Verifying in database...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM tuning_prompt_templates ORDER BY name")
    db_templates = cursor.fetchall()
    conn.close()

    print(f"✓ Total templates in database: {len(db_templates)}")

    # Expected template names based on what we extracted
    extracted_names = [t['name'] for t in templates]

    # Check which ones we have
    db_names = [row[0] for row in db_templates]
    missing = [name for name in extracted_names if name not in db_names]

    if missing:
        print(f"\n⚠ Missing expected templates: {missing}")
    else:
        print(f"\n✅ All {len(extracted_names)} creative templates are in the database!")

    # Also list any templates in DB that weren't in our extraction
    extras = [name for name in db_names if name not in extracted_names and not name.startswith('standard_')]
    if extras:
        print(f"\n📦 Additional templates in database (not from creative set): {extras}")

    return 0

if __name__ == "__main__":
    exit(main())