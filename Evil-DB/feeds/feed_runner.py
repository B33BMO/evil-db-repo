import requests
import sqlite3
from datetime import datetime
import os
import sys

print("==== FEED RUNNER DEBUG ====")
print("cwd:", os.getcwd())
print("script dir:", os.path.dirname(os.path.abspath(__file__)))
print("DB_PATH:", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../db/threats.db")))
print("user:", os.getuid() if hasattr(os, "getuid") else "windows?")
print("python:", sys.executable)
print("===========================")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "db", "threats.db")
def neutrino_blocklist():
    print("🛡️  Neutrino API Blocklist Bulk Download…")
    user_id = "b33bmo"
    api_key = "m8Jm8MF4qhXJqWE8cS6xJVeb9I2dvU46TN3EShO6E800FC9Z"
    url = "https://neutrinoapi.net/ip-blocklist-download"
    try:
        resp = requests.post(url, data={"user-id": user_id, "api-key": api_key}, timeout=60)
        resp.raise_for_status()
        count = 0
        for ip in resp.text.splitlines():
            ip = ip.strip()
            if not ip or ip.startswith("#"):
                continue
            insert_ip(ip, "blocklist", "neutrino_bulk", "high", "Neutrino bulk blocklist")
            count += 1
            if count % 10000 == 0:
                print(f"  ...imported {count} IPs so far")
        print(f"✅ Neutrino bulk: {count} IPs imported")
    except Exception as e:
        print(f"❌ Neutrino blocklist download failed: {e}")

def dedupe_and_index():
    print("🧹 Deduplicating and indexing database...")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    DELETE FROM threat_indicators
    WHERE rowid NOT IN (
      SELECT MIN(rowid)
      FROM threat_indicators
      GROUP BY type, value, category, source
    );
    """)
    conn.commit()
    cur.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_threat
    ON threat_indicators(type, value, category, source);
    """)
    conn.commit()
    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_threat_value
    ON threat_indicators(value);
    """)
    conn.commit()
    print("✅ Deduplication and indexing complete.")
    conn.close()

def ensure_fts():
    """Make sure FTS5 table exists and is synced to the main table."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Create FTS5 table if not exists
    cur.execute("""
    CREATE VIRTUAL TABLE IF NOT EXISTS threat_indicators_fts USING fts5(
        value, category, source, severity, notes, 
        content='threat_indicators', content_rowid='rowid'
    );
    """)
    conn.commit()
    # If it’s empty or out of sync, repopulate
    cur.execute("SELECT COUNT(*) FROM threat_indicators_fts")
    fts_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threat_indicators")
    tbl_count = cur.fetchone()[0]
    if fts_count != tbl_count or fts_count == 0:
        print("🔄 Resyncing FTS index (this may take a second)...")
        cur.execute("DELETE FROM threat_indicators_fts")
        conn.commit()
        cur.execute("""
        INSERT INTO threat_indicators_fts(rowid, value, category, source, severity, notes)
        SELECT rowid, value, category, source, severity, notes FROM threat_indicators
        """)
        conn.commit()
        print(f"✅ Synced FTS: {tbl_count} rows")
    else:
        print(f"FTS index already synced ({fts_count} rows)")
    conn.close()

def insert_ip(ip, category, source, severity="high", notes=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT OR IGNORE INTO threat_indicators (type, value, category, source, first_seen, severity, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "ip", ip, category, source,
            datetime.utcnow().strftime("%Y-%m-%d"),
            severity, notes
        ))
        conn.commit()
    except sqlite3.DatabaseError as e:
        print(f"❌ DB error while inserting {ip}: {e}")
    finally:
        conn.close()

def get_feed_lines(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
    except requests.RequestException as e:
        print(f"❌ Failed to fetch {url}: {e}")
        return []

# --- [feed fetch functions same as before, omitted for brevity, keep all yours here!] ---

def run_all_feeds():
    dedupe_and_index()
    print("Downloading Neutrino Data")
    neutrino_blocklist()
    print("🚀 Starting EvilWatch Feed Importer")
    firehol_level1()
    blocklist_de()
    artillery_banlist()
    malwaredomainlist()
    ciarmy()
    tor_exit_nodes()
    abusech()
    emerging_threats()
    spamhaus_drop()
    alienvault_otx()
    cisco_talos()
    openphish()
    blocklistpro()
    sans_dshield()
    abusech_sslbl()
    cybercrime_tracker()
    urlhaus()
    print("✅ Done.")
    dedupe_and_index()
    ensure_fts()  # <-- Sync to FTS every run!

def search_fts(term):
    """Quick CLI: search the FTS table for term and print top 10 matches."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    print(f"🔍 Searching FTS for: {term}")
    cur.execute("""
        SELECT value, category, source, severity, notes
        FROM threat_indicators_fts
        WHERE threat_indicators_fts MATCH ?
        LIMIT 10
    """, (term,))
    rows = cur.fetchall()
    if not rows:
        print("No results found.")
    for row in rows:
        print(f"- {row[0]} [{row[1]}] ({row[2]}): {row[3]} | {row[4]}")
    conn.close()

def print_usage():
    print("Usage: python feed_runner.py [import|rebuild-fts|search-fts <term>]")
    print("  import       -- run all feeds and sync FTS (default)")
    print("  rebuild-fts  -- rebuild/refresh the FTS5 index only")
    print("  search-fts   -- search FTS5 index for a term")

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "import":
        run_all_feeds()
    elif args[0] == "rebuild-fts":
        ensure_fts()
    elif args[0] == "search-fts" and len(args) > 1:
        ensure_fts()
        search_fts(args[1])
    else:
        print_usage()
