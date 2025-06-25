from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import os
import feedparser
import requests
router = APIRouter()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "db", "threats.db")

class ThreatCheckResponse(BaseModel):
    match: bool
    value: str
    category: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None

def query_threat_db(indicator_type: str, value: str) -> ThreatCheckResponse:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    cur = conn.cursor()
    cur.execute("SELECT category, source, severity, notes FROM threat_indicators WHERE type=? AND value=?", (indicator_type, value))
    row = cur.fetchone()
    conn.close()
    if row:
        return ThreatCheckResponse(match=True, value=value, category=row[0], source=row[1], severity=row[2], notes=row[3])
    return ThreatCheckResponse(match=False, value=value)

@router.get("/check", response_model=ThreatCheckResponse)
def check_threat(type: str = Query(..., pattern="^(ip|email|domain)$"), value: str = Query(...)):
    return query_threat_db(type, value)

@router.get("/list", response_model=List[ThreatCheckResponse])
def list_threats(limit: int = 100):
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    cur = conn.cursor()
    cur.execute("SELECT value, category, source, severity, notes FROM threat_indicators LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [
        ThreatCheckResponse(match=True, value=row[0], category=row[1], source=row[2], severity=row[3], notes=row[4])
        for row in rows
    ]

@router.get("/search", response_model=List[ThreatCheckResponse])
def search_threats(q: str, limit: int = 50):
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
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
@router.get("/fallback")
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
                auth=(os.getenv("NEUTRINO_USER", ""), os.getenv("NEUTRINO_KEY", ""))
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

@router.get("/stats/entries")
def get_entry_count():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threat_indicators")
    count = cur.fetchone()[0]
    conn.close()
    return {"count": count}

@router.get("/stats/searches")
def get_search_count():
    return {"count": 42}  # Replace with real logic

@router.get("/rss/cves")
def get_recent_cves():
    feed_url = "https://cvefeed.io/rssfeed/latest.xml"
    feed = feedparser.parse(feed_url)
    print(f"CVEs fetched: {len(feed.entries)}")  # Debug print

    items = []
    for entry in feed.entries[:10]:
        title = getattr(entry, "title", "No Title")
        link = getattr(entry, "link", "#")
        items.append({"title": title, "link": link})

    # If nothing, return some spicy sample data to prove the UI works
    if not items:
        print("CVEs EMPTY! Returning mock data.")
        items = [
            {"title": "CVE-2025-99999: The Universe Exploded", "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-99999"},
            {"title": "CVE-2025-12345: WebApp Buffer Overflow", "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-12345"},
            {"title": "CVE-2025-13337: Elite Hackz0r Escalation", "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-13337"},
        ]

    return {"items": items}

search_counter = 0

@router.get("/stats/type-breakdown")
def type_breakdown():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    cur = conn.cursor()
    cur.execute("SELECT category, COUNT(*) FROM threat_indicators GROUP BY category")
    rows = cur.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}
@router.get("/enrich")
def enrich_ip(ip: str):
    # 1. Try to find in DB as type="ip"
    result = query_threat_db("ip", ip)
    
    # 2. GeoIP enrichment
    geo_data = {}
    try:
        geo_res = requests.get(f"http://ip-api.com/json/{ip}")
        if geo_res.ok:
            geo_data = geo_res.json()
    except Exception as e:
        print(f"GeoIP error: {e}")

    # 3. Neutrino enrichment
    neutrino_data = {}
    try:
        user = os.getenv("NEUTRINO_USER", "")
        key = os.getenv("NEUTRINO_KEY", "")
        r = requests.post(
            "https://neutrinoapi.net/ip-blocklist",
            data={"ip": ip},
            auth=(user, key)
        )
        if r.ok:
            neutrino_data = r.json()
    except Exception as e:
        print(f"Neutrino error: {e}")

    return {
        "db": result.dict(),
        "geo": geo_data,
        "neutrino": neutrino_data,
    }