import sqlite3
import os

DB_PATH = "backend/scans.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# List of prompts I want to remove (duplicates of v21+)
duplicates = [
    "v2_chain_of_thought",
    "v2_adversarial", 
    "v2_minimalist",
    "v2_skeptic",
    "v2_maintainer",
    "v2_data_flow",
    "v2_security_standards",
    "v2_json_only"
]

print("Cleaning up duplicate prompts...")
for name in duplicates:
    c.execute("DELETE FROM tuning_prompt_templates WHERE name = ?", (name,))
    if c.rowcount > 0:
        print(f"Deleted {name}")

conn.commit()
conn.close()
print("Cleanup complete.")