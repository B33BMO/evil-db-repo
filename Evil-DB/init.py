import sqlite3

conn = sqlite3.connect("/Users/brandonbischoff/evil-db/Evil-DB/db/threats.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS threat_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('ip', 'email', 'domain')),
    value TEXT NOT NULL,
    category TEXT,
    source TEXT,
    first_seen TEXT,
    last_seen TEXT,
    severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    notes TEXT
)
""")

conn.commit()
conn.close()
