#!/usr/bin/env python3
"""
Populate full_code_chunk for test cases by reading actual source files
"""
import sqlite3


def extract_context(file_path: str, target_line: int, context_lines: int = 50) -> str:
    """Read file and extract context around target line"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        if target_line < 1 or target_line > len(lines):
            return None

        # Extract surrounding context
        start = max(0, target_line - context_lines - 1)
        end = min(len(lines), target_line + context_lines)

        context_lines_list = []
        for i in range(start, end):
            # Mark the target line
            prefix = ">>> " if i == target_line - 1 else "    "
            context_lines_list.append(f"{prefix}{i+1}: {lines[i].rstrip()}")

        return '\n'.join(context_lines_list)
    except Exception as e:
        print(f"    Error reading {file_path}: {e}")
        return None


def main():
    db_path = "/home/aiadmin/web-davy-code-scanner/backend/data/scans.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get test cases without full code
    cursor.execute("""
        SELECT id, name, file_path, line_number
        FROM tuning_test_cases
        WHERE full_code_chunk IS NULL OR full_code_chunk = ''
    """)

    test_cases = cursor.fetchall()
    print(f"\n🔍 Found {len(test_cases)} test cases without full_code_chunk\n")

    success_count = 0

    for tc_id, name, file_path_raw, line_number in test_cases:
        # Parse file path
        if not file_path_raw:
            print(f"  ❌ {name}: No file_path")
            continue

        if ':' in file_path_raw:
            file_path, line_str = file_path_raw.rsplit(':', 1)
            try:
                line_number = int(line_str)
            except ValueError:
                file_path = file_path_raw
        else:
            file_path = file_path_raw

        if not line_number:
            print(f"  ❌ {name}: No line number")
            continue

        # Find scan file with this path
        cursor.execute("""
            SELECT id, scan_id, file_path
            FROM scan_files
            WHERE file_path LIKE ?
            ORDER BY scan_id DESC
            LIMIT 1
        """, (f"%{file_path}",))

        result = cursor.fetchone()
        if not result:
            print(f"  ❌ {name}: File not found: {file_path}")
            continue

        scan_file_id, scan_id, full_file_path = result

        # Extract context from actual file
        context = extract_context(full_file_path, line_number, context_lines=50)

        if not context:
            print(f"  ⚠️  {name}: Failed to extract context")
            continue

        # Update test case
        cursor.execute("""
            UPDATE tuning_test_cases
            SET full_code_chunk = ?,
                source_scan_id = ?,
                file_path = ?,
                line_number = ?
            WHERE id = ?
        """, (context, scan_id, full_file_path, line_number, tc_id))
        conn.commit()

        print(f"  ✅ {name}: {len(context)} chars from scan {scan_id}")
        success_count += 1

    conn.close()
    print(f"\n✨ Populated {success_count}/{len(test_cases)} test cases\n")


if __name__ == "__main__":
    main()
