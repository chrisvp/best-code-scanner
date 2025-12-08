from sqlalchemy import create_engine, text
import os

DB_URL = "sqlite:////tmp/scans.db"

try:
    engine = create_engine(DB_URL)
    with engine.connect() as connection:
        scan_id = 156
        
        # Get config
        print(f"Checking Config for Scan {scan_id}:")
        config = connection.execute(text(f"SELECT analysis_mode, scope, profile_id FROM scan_configs WHERE scan_id = {scan_id}")).fetchone()
        
        if config:
            print(f"  - Mode: {config[0]}")
            print(f"  - Scope: {config[1]}")
            profile_id = config[2]
            print(f"  - Profile ID: {profile_id}")
            
            if profile_id:
                profile = connection.execute(text(f"SELECT name, first_phase_method, joern_query_set FROM scan_profiles WHERE id = {profile_id}")).fetchone()
                if profile:
                    print(f"  - Profile Name: {profile[0]}")
                    print(f"  - Phase Method: {profile[1]}")
                    print(f"  - Joern Query Set: {profile[2]}")
                else:
                    print("  - Profile not found")
            else:
                print("  - No profile used")
        else:
            print("  - No config found")

except Exception as e:
    print(f"Error: {e}")
