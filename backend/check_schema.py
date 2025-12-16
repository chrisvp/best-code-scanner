import sqlite3
import os

DB_PATH = "backend/scans.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("PRAGMA table_info(draft_findings)")
columns = c.fetchall()
for col in columns:
    print(col)
conn.close()