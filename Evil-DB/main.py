from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import os
import requests
import feedparser
from routes import api, neutrino
import threading
import time
import subprocess
from contextlib import asynccontextmanager

from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "threats.db")

NEUTRINO_USER = "b33bmo"
NEUTRINO_KEY = "m8Jm8MF4qhXJqWE8cS6xJVeb9I2dvU46TN3EShO6E800FC9Z"

app = FastAPI(
    title="EvilWatch API",
    version="0.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---
class ThreatCheckResponse(BaseModel):
    match: bool
    value: str
    category: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None

# --- FTS5 Migration & Sync ---
def migrate_and_sync_fts():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Enable WAL for better concurrency
    cur.execute("PRAGMA journal_mode=WAL;")
    # Create FTS5 table if it doesn't exist
    cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS threat_indicators_fts USING fts5(
            value, category, source, severity, notes, content='threat_indicators', content_rowid='rowid'
        )
    """)
    # Sync: Insert new rows not already in FTS
    cur.execute("""
        INSERT INTO threat_indicators_fts (rowid, value, category, source, severity, notes)
        SELECT rowid, value, category, source, severity, notes FROM threat_indicators
        WHERE rowid NOT IN (SELECT rowid FROM threat_indicators_fts)
    """)
    # Regular indexes for other fast queries (leave these!)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_type_value ON threat_indicators(type, value);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_value ON threat_indicators(value);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_category ON threat_indicators(category);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_source ON threat_indicators(source);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notes ON threat_indicators(notes);")
    conn.commit()
    conn.close()

def check_db():
    if not os.path.exists(DB_PATH):
        raise RuntimeError(f"Database not found at {DB_PATH}")
    migrate_and_sync_fts()

def run_feed_runner_periodically():
    while True:
        try:
            print("[FeedRunner] Running feed_runner.py…")
            subprocess.run(["python3", "./feeds/feed_runner.py"], check=True)
            print("[FeedRunner] Done. Syncing FTS5 table…")
            migrate_and_sync_fts()
            print("[FeedRunner] FTS5 sync complete. Sleeping for 10 minutes.")
        except Exception as e:
            print(f"[FeedRunner] Error: {e}")
        time.sleep(600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    check_db()
    thread = threading.Thread(target=run_feed_runner_periodically, daemon=True)
    thread.start()
    yield

app.router.lifespan_context = lifespan

app.include_router(api.router, prefix="/api")
app.include_router(neutrino.router, prefix="/neutrino")

# --- Helper ---
def query_threat_db(indicator_type: str, value: str) -> ThreatCheckResponse:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT category, source, severity, notes FROM threat_indicators WHERE type=? AND value=?",
        (indicator_type, value)
    )
    row = cur.fetchone()
    conn.close()
    if row:
        return ThreatCheckResponse(match=True, value=value, category=row[0], source=row[1], severity=row[2], notes=row[3])
    else:
        return ThreatCheckResponse(match=False, value=value)

@app.get("/check", response_model=ThreatCheckResponse)
def check_threat(
    type: str = Query(..., pattern="^(ip|email|domain)$"),
    value: str = Query(...)
):
    return query_threat_db(type, value)

@app.get("/list", response_model=List[ThreatCheckResponse])
def list_threats(limit: int = 100):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value, category, source, severity, notes FROM threat_indicators LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [
        ThreatCheckResponse(match=True, value=row[0], category=row[1], source=row[2], severity=row[3], notes=row[4])
        for row in rows
    ]

@app.get("/search", response_model=List[ThreatCheckResponse])
def search_threats(q: str, limit: int = 50):
    import time as _time
    start = _time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # -- 1. Exact match (fast, indexed)
    cur.execute("""
        SELECT value, category, source, severity, notes
        FROM threat_indicators
        WHERE value = ?
        LIMIT ?
    """, (q, limit))
    rows = cur.fetchall()
    # -- 2. Starts-with match (still uses index)
    if not rows:
        cur.execute("""
            SELECT value, category, source, severity, notes
            FROM threat_indicators
            WHERE value LIKE ?
            LIMIT ?
        """, (f"{q}%", limit))
        rows = cur.fetchall()
    # -- 3. Contains (fuzzy, SLOW, last resort)
    if not rows:
        cur.execute("""
            SELECT value, category, source, severity, notes
            FROM threat_indicators
            WHERE value LIKE ?
            LIMIT ?
        """, (f"%{q}%", limit))
        rows = cur.fetchall()
    conn.close()
    print(f"[Search] Took {_time.time() - start:.3f} sec for query: {q} [{len(rows)} results]")
    return [
        ThreatCheckResponse(match=True, value=row[0], category=row[1], source=row[2], severity=row[3], notes=row[4])
        for row in rows
    ]



@app.get("/stats/entries")
def get_entry_count():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT value) FROM threat_indicators")
        count = cur.fetchone()[0]
        conn.close()
        return {"count": count}
    except Exception as e:
        print("DB ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats/searches")
def get_search_count():
    # Replace with real logic later
    return {"count": 42}

@app.get("/rss/cves")
def get_recent_cves():
    feed_url = "https://cvefeed.io/rssfeed/latest.xml"
    feed = feedparser.parse(feed_url)
    return {"items": [
        {"title": entry.title, "link": entry.link}
        for entry in feed.entries[:10]
    ]}

search_counter = 0

@app.post("/api/stats/increment-search")
def increment_search():
    global search_counter
    search_counter += 1
    return {"count": search_counter}

@app.get("/stats/type-breakdown")
def get_type_breakdown():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT category, COUNT(*) FROM threat_indicators GROUP BY category")
    rows = cur.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}
