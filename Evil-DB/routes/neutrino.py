# /routes/neutrino.py
from fastapi import APIRouter, Request
from pydantic import BaseModel
import os
import sqlite3
import requests

router = APIRouter()

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "threats.db")
NEUTRINO_USER = os.getenv("NEUTRINO_USER", "")
NEUTRINO_KEY = os.getenv("NEUTRINO_KEY", "")

class SaveRequest(BaseModel):
    ip: str
    data: dict

@router.get("/cache")
def get_cached(ip: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT data FROM neutrino_cache WHERE ip=?", (ip,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else {}

@router.get("/live")
def get_live(ip: str):
    res = requests.post(
        "https://neutrinoapi.net/ip-blocklist",
        data={"ip": ip},
        auth=(NEUTRINO_USER, NEUTRINO_KEY)
    )
    if not res.ok:
        return {"error": "Failed to fetch from Neutrino"}
    return res.json()

@router.post("/save")
def save_data(req: SaveRequest):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS neutrino_cache (ip TEXT PRIMARY KEY, data TEXT)")
    cur.execute("INSERT OR REPLACE INTO neutrino_cache (ip, data) VALUES (?, ?)", (req.ip, str(req.data)))
    conn.commit()
    conn.close()
    return {"status": "saved"}
