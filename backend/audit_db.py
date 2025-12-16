import sqlite3
import json
import os

DB_PATH = "backend/scans.db"

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

if not os.path.exists(DB_PATH):
    print(f"Database file {DB_PATH} not found!")
    exit(1)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = dict_factory
c = conn.cursor()

print("=== 1. LATEST SCAN ===")
try:
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    scan = c.fetchone()
    print(json.dumps(scan, indent=2, default=str))

    if not scan:
        print("No scans found.")
        exit()

    scan_id = scan['id']

    print(f"\n=== 2. VERIFIER CONFIGS (Profile Verifiers) ===")
    # Check if profile_verifiers table exists (it might be new schema)
    try:
        c.execute("""
            SELECT pv.id, pv.name, pv.prompt_template, m.name as model_name, pv.enabled
            FROM profile_verifiers pv
            JOIN model_configs m ON pv.model_id = m.id
            WHERE pv.enabled = 1
        """)
        verifiers = c.fetchall()
        print(json.dumps(verifiers, indent=2))
    except Exception as e:
        print(f"Error querying profile_verifiers: {e}")
        
    print(f"\n=== 2b. MODEL CONFIGS (Verifiers) ===")
    c.execute("SELECT id, name, verification_prompt_template FROM model_configs WHERE is_verifier = 1")
    configs = c.fetchall()
    
    # Print full prompt for the first model, truncated for others
    # for i, conf in enumerate(configs):
    #     if conf['verification_prompt_template']:
    #         if i == 0:
    #             print(f"--- Full Prompt for {conf['name']} ---")
    #             print(conf['verification_prompt_template'])
    #             print("---------------------------------------")
    #         else:
    #             conf['verification_prompt_template'] = conf['verification_prompt_template'][:100] + "... (truncated)"
    
    print(json.dumps(configs, indent=2))

    print(f"\n=== 3. DRAFT FINDINGS (Scan {scan_id}) ===")
    c.execute("""
        SELECT id, title, vulnerability_type, severity, status, line_number, snippet, reason
        FROM draft_findings
        WHERE scan_id = ?
        ORDER BY id DESC
        LIMIT 20
    """, (scan_id,))
    findings = c.fetchall()
    for f in findings:
        if f['snippet']: f['snippet'] = f['snippet'][:100] + "..."
        if f['reason']: f['reason'] = f['reason'][:100] + "..."
    
    print(f"Found {len(findings)} findings (showing last 20):")
    print(json.dumps(findings, indent=2))

    print(f"\n=== 4. VERIFIER LOGS (Scan {scan_id}) ===")
    c.execute("""
        SELECT model_name, request_prompt, raw_response, duration_ms, created_at
        FROM llm_request_logs
        WHERE scan_id = ? AND phase = 'verifier'
        ORDER BY id DESC
        LIMIT 5
    """, (scan_id,))
    logs = c.fetchall()
    
    print(f"Found {len(logs)} verifier logs.")
    
    if logs:
        print("\n--- SAMPLE VERIFIER PROMPT (First Log) ---")
        print(logs[0]['request_prompt'])
        print("\n--- SAMPLE VERIFIER RESPONSE (First Log) ---")
        print(logs[0]['raw_response'])
        print("------------------------------------------")

    # Aggregate stats from logs if possible
    print(f"\n=== 5. VERIFIER STATS (Scan {scan_id}) ===")
    c.execute("""
        SELECT model_name, count(*) as count
        FROM llm_request_logs
        WHERE scan_id = ? AND phase = 'verifier'
        GROUP BY model_name
    """, (scan_id,))
    stats = c.fetchall()
    print(json.dumps(stats, indent=2))

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    conn.close()
