from fastapi import FastAPI, HTTPException, Query
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import sqlite3
import threading
import os

app = FastAPI()

DB_PATH = "signals.db"
SECRET_KEY = "supersecret123"

SIGNAL_TTL_SECONDS = 120  # 🔥 NEU

lock = threading.Lock()


# ---------------- DB ----------------

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol TEXT,
        side TEXT,
        score REAL,
        created_utc TEXT,
        status TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS signal_acks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signal_id INTEGER,
        account TEXT,
        magic TEXT,
        ack_time TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------------- FILTER ----------------

def apply_score_filter(score: float):
    if score < 0.6:
        return False, "SCORE_LT_0_60"
    return True, "APPROVED"


# ---------------- POST /tv ----------------

@app.post("/tv")
def tv_signal(data: Dict[str, Any]):
    if data.get("key") != SECRET_KEY:
        raise HTTPException(403, "Invalid key")

    symbol = data.get("symbol")
    side = data.get("side")
    score = float(data.get("score", 0))

    approved, reason = apply_score_filter(score)

    now = datetime.now(timezone.utc).isoformat()

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    INSERT INTO signals (symbol, side, score, created_utc, status)
    VALUES (?, ?, ?, ?, ?)
    """, (symbol, side, score, now, "pending"))

    signal_id = c.lastrowid

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "signal_id": signal_id,
        "approved": approved,
        "reason": reason
    }


# ---------------- GET /latest ----------------

@app.get("/latest")
def latest(symbol: str, account: str, magic: str):

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    SELECT id, symbol, side, score, created_utc, status
    FROM signals
    WHERE symbol = ?
    ORDER BY id DESC LIMIT 1
    """, (symbol,))

    row = c.fetchone()

    if not row:
        return {"has_signal": False}

    signal_id, symbol, side, score, created_utc, status = row

    created_dt = datetime.fromisoformat(created_utc)
    age = (datetime.now(timezone.utc) - created_dt).total_seconds()

    # 🔥 TTL CHECK
    if age > SIGNAL_TTL_SECONDS:
        return {
            "has_signal": False,
            "blocked": True,
            "reason": "TTL_EXPIRED"
        }

    approved, reason = apply_score_filter(score)

    if not approved:
        return {
            "has_signal": False,
            "blocked": True,
            "reason": reason,
            "score": score
        }

    # 🔥 PER ACCOUNT CHECK
    c.execute("""
    SELECT 1 FROM signal_acks
    WHERE signal_id=? AND account=? AND magic=?
    """, (signal_id, account, magic))

    already = c.fetchone()

    if already:
        return {
            "has_signal": False,
            "blocked": True,
            "reason": "ALREADY_EXECUTED"
        }

    return {
        "has_signal": True,
        "signal": {
            "id": signal_id,
            "symbol": symbol,
            "side": side,
            "score": score
        }
    }


# ---------------- POST /ack ----------------

@app.post("/ack")
def ack(symbol: str, signal_id: int, account: str, magic: str):

    now = datetime.now(timezone.utc).isoformat()

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    INSERT INTO signal_acks (signal_id, account, magic, ack_time)
    VALUES (?, ?, ?, ?)
    """, (signal_id, account, magic, now))

    conn.commit()
    conn.close()

    return {"ok": True}
