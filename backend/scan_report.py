from sqlalchemy import create_engine, text

engine = create_engine('sqlite:////tmp/scans.db')
with engine.connect() as conn:
    print('=== SCAN SUMMARY ===')
    scans = conn.execute(text('''
        SELECT s.id, s.target_url, s.status, s.created_at,
               (SELECT COUNT(*) FROM draft_findings WHERE scan_id = s.id) as drafts,
               (SELECT COUNT(*) FROM verified_findings WHERE scan_id = s.id AND status = "complete") as findings
        FROM scans s ORDER BY s.id DESC
    ''')).fetchall()

    for s in scans:
        url = s[1].split('/')[-1] if '/' in s[1] else s[1][:30]
        print(f'Scan {s[0]}: {url} - {s[3]} | Drafts: {s[4]}, Findings: {s[5]}')

    print('\n=== SEVERITY BREAKDOWN ===')
    breakdown = conn.execute(text('''
        SELECT scan_id, adjusted_severity, COUNT(*) as count
        FROM verified_findings
        WHERE status = "complete"
        GROUP BY scan_id, adjusted_severity
        ORDER BY scan_id DESC, adjusted_severity
    ''')).fetchall()

    current_scan = None
    for row in breakdown:
        if row[0] != current_scan:
            current_scan = row[0]
            print(f'Scan {row[0]}:')
        print(f'  {row[1]}: {row[2]}')
