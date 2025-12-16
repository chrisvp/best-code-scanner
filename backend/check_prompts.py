import sqlite3
import os

DB_PATH = "backend/scans.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("SELECT name FROM tuning_prompt_templates WHERE name LIKE 'v2%' ORDER BY name")
rows = c.fetchall()
print("Prompts in DB starting with v2:")
for r in rows:
    print(r[0])
conn.close()