from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import os
import requests
import feedparser
from fastapi import FastAPI
from routes import api, neutrino
import threading
import time
import subprocess


app = FastAPI(title="EvilWatch API", version="0.1")
app.include_router(api.router, prefix="/api")
app.include_router(neutrino.router, prefix="/neutrino")
@app.on_event("startup")
def startup_tasks():
    check_db()
    thread = threading.Thread(target=run_feed_runner_periodically, daemon=True)
    thread.start()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "threats.db")

# Optional: Environment variables for Neutrino credentials
NEUTRINO_API_USER = os.getenv("NEUTRINO_USER", "")
NEUTRINO_API_KEY = os.getenv("NEUTRINO_KEY", "")

class ThreatCheckResponse(BaseModel):
    match: bool
    value: str
    category: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None

def query_threat_db(indicator_type: str, value: str) -> ThreatCheckResponse:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT category, source, severity, notes FROM threat_indicators WHERE type=? AND value=?", (indicator_type, value))
    row = cur.fetchone()
    conn.close()

    if row:
        return ThreatCheckResponse(match=True, value=value, category=row[0], source=row[1], severity=row[2], notes=row[3])
    else:
        return ThreatCheckResponse(match=False, value=value)

@app.on_event("startup")
def check_db():
    if not os.path.exists(DB_PATH):
        raise RuntimeError(f"Database not found at {DB_PATH}")

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
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    like_query = f"%{q}%"
    cur.execute("""
        SELECT value, category, source, severity, notes
        FROM threat_indicators
        WHERE value LIKE ? OR category LIKE ? OR source LIKE ? OR notes LIKE ?
        LIMIT ?
    """, (like_query, like_query, like_query, like_query, limit))
    rows = cur.fetchall()
    conn.close()
    return [
        ThreatCheckResponse(match=True, value=row[0], category=row[1], source=row[2], severity=row[3], notes=row[4])
        for row in rows
    ]

@app.get("/stats/entries")
def get_entry_count():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Count only unique entries by value
    cur.execute("SELECT COUNT(DISTINCT value) FROM threat_indicators")
    count = cur.fetchone()[0]
    conn.close()
    return {"count": count}

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

@app.get("/fallback")
def fallback_search(value: str):
    result = query_threat_db("ip", value)
    geo_data = {}
    neutrino_data = {}

    if not result.match:
        # GeoIP
        try:
            geo_res = requests.get(f"http://ip-api.com/json/{value}")
            if geo_res.ok:
                geo_data = geo_res.json()
        except Exception as e:
            print(f"GeoIP error: {e}")

        # Neutrino
        try:
            r = requests.post(
                "https://neutrinoapi.net/ip-blocklist",
                data={"ip": value},
                auth=(NEUTRINO_API_USER, NEUTRINO_API_KEY)
            )
            if r.ok:
                neutrino_data = r.json()
        except Exception as e:
            print(f"Neutrino error: {e}")

        if not neutrino_data:
            try:
                ipqs_key = os.getenv("IPQS_KEY", "")
                r = requests.get(
                    f"https://ipqualityscore.com/api/json/ip/{ipqs_key}/{value}"
                )
                if r.ok:
                    neutrino_data = r.json()
                    neutrino_data["source"] = "ipqualityscore"
            except Exception as e:
                print(f"IPQS fallback error: {e}")

    return {
        "db_match": result.dict(),
        "geo": geo_data,
        "neutrino": neutrino_data,
        "source_used": neutrino_data.get("source", "none")
    }
@app.get("/stats/type-breakdown")
def get_type_breakdown():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT category, COUNT(*) FROM threat_indicators GROUP BY category")
    rows = cur.fetchall()
    conn.close()
    # Return as a dict {category: count}
    return {row[0]: row[1] for row in rows}
def run_feed_runner_periodically():
    while True:
        try:
            print("[FeedRunner] Running feed_runner.py…")
            subprocess.run(["python3", "./feeds/feed_runner.py"], check=True)
            print("[FeedRunner] Done. Sleeping for 10 minutes.")
        except Exception as e:
            print(f"[FeedRunner] Error: {e}")
        time.sleep(600)  # 600 seconds = 10 minutes