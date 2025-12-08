from sqlalchemy import create_engine, text
import os

# Database URL (assuming default sqlite location from context)
DB_URL = "sqlite:////tmp/scans.db"

try:
    engine = create_engine(DB_URL)
    with engine.connect() as connection:
        # Get most recent scan
        result = connection.execute(text("SELECT id, target_url, status, created_at FROM scans ORDER BY created_at DESC LIMIT 1"))
        scan = result.fetchone()
        
        if scan:
            print(f"Most Recent Scan:")
            print(f"ID: {scan[0]}")
            print(f"Target: {scan[1]}")
            print(f"Status: {scan[2]}")
            print(f"Created At: {scan[3]}")
            
            scan_id = scan[0]
            
            # Check for Joern logs
            print(f"\nChecking LLMRequestLog for Scan ID {scan_id} (looking for Joern entries):")
            logs = connection.execute(text(f"SELECT id, model_name, phase, status, created_at FROM llm_request_logs WHERE scan_id = {scan_id} AND model_name LIKE '%Joern%' ORDER BY created_at DESC"))
            joern_logs = logs.fetchall()
            
            if joern_logs:
                for log in joern_logs:
                    print(f"  - Log ID: {log[0]}, Model: {log[1]}, Phase: {log[2]}, Status: {log[3]}, Time: {log[4]}")
            else:
                print("  No Joern logs found for this scan.")
                
        else:
            print("No scans found in the database.")
            
except Exception as e:
    print(f"Error: {e}")
