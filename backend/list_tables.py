import sqlite3
import os

DB_PATH = "backend/scans.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = c.fetchall()
print("Tables:")
for t in tables:
    print(f"- {t[0]}")
conn.close()