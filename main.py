from fastapi import FastAPI, HTTPException, Query, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Dict, List
from jose import jwt, JWTError
import os
import sqlite3
import threading
import json

app = FastAPI(title="Signal Agent API", version="6.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
DB_PATH = os.getenv("DB_PATH", "signal_agent.db")
DEFAULT_GATE_LEVEL = os.getenv("DEFAULT_GATE_LEVEL", "GREEN").upper()
HEARTBEAT_TIMEOUT_SEC = int(os.getenv("HEARTBEAT_TIMEOUT_SEC", "90"))

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "123456")

# Optional app token protection for dashboard routes
APP_TOKEN = os.getenv("APP_TOKEN", "").strip()
APP_TOKEN_HEADER = os.getenv("APP_TOKEN_HEADER", "X-APP-TOKEN").strip() or "X-APP-TOKEN"

# TV/API key
TV_API_KEY = os.getenv("TV_API_KEY", SECRET_KEY)

# Controls / manual overrides
DEFAULT_ALLOW_NEW_ENTRIES = os.getenv("DEFAULT_ALLOW_NEW_ENTRIES", "true").lower() == "true"
DEFAULT_RISK_MULTIPLIER = float(os.getenv("DEFAULT_RISK_MULTIPLIER", "1.0"))
DEFAULT_PAUSED = os.getenv("DEFAULT_PAUSED", "false").lower() == "true"

# KPI CONFIG
DEFAULT_KPI_LOOKBACK_DAYS = int(os.getenv("DEFAULT_KPI_LOOKBACK_DAYS", "7"))
DEFAULT_KPI_LIMIT_TRADES = int(os.getenv("DEFAULT_KPI_LIMIT_TRADES", "50"))

AUTO_GATE_ENABLED = os.getenv("AUTO_GATE_ENABLED", "true").lower() == "true"

YELLOW_DD_PCT = float(os.getenv("YELLOW_DD_PCT", "3.0"))
RED_DD_PCT = float(os.getenv("RED_DD_PCT", "6.0"))

YELLOW_LOSS_STREAK = int(os.getenv("YELLOW_LOSS_STREAK", "3"))
RED_LOSS_STREAK = int(os.getenv("RED_LOSS_STREAK", "5"))

YELLOW_R_SUM = float(os.getenv("YELLOW_R_SUM", "-2.0"))
RED_R_SUM = float(os.getenv("RED_R_SUM", "-4.0"))

YELLOW_WINRATE_MIN = float(os.getenv("YELLOW_WINRATE_MIN", "35.0"))
RED_WINRATE_MIN = float(os.getenv("RED_WINRATE_MIN", "25.0"))

DB_LOCK = threading.Lock()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# -------------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(dt: Optional[datetime] = None) -> str:
    if dt is None:
        dt = now_utc()
    return dt.astimezone(timezone.utc).isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = dict_factory
    return conn


def safe_float(x, default=0.0):
    try:
        if x is None or x == "":
            return default
        return float(x)
    except Exception:
        return default


def safe_int(x, default=0):
    try:
        if x is None or x == "":
            return default
        return int(x)
    except Exception:
        return default


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = now_utc() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    return {"username": username}


def app_token_guard(x_app_token: Optional[str] = Header(default=None, alias=APP_TOKEN_HEADER)):
    if APP_TOKEN:
        if x_app_token != APP_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid app token")
    return True


def get_runtime_controls(symbol: Optional[str] = None) -> Dict[str, Any]:
    return {
        "paused": DEFAULT_PAUSED,
        "allow_new_entries": DEFAULT_ALLOW_NEW_ENTRIES,
        "risk_multiplier": DEFAULT_RISK_MULTIPLIER,
        "symbol": symbol.upper() if symbol else None,
        "source": "default_env"
    }


def normalize_side(value: Optional[str]) -> str:
    s = (value or "").strip().upper()
    if s == "LONG":
        s = "BUY"
    elif s == "SHORT":
        s = "SELL"
    return s


def signal_passes_filter(signal_row: Dict[str, Any], gate_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = signal_row.get("payload", {}) or {}
    score = safe_float(payload.get("score"), 1.0)

    gate_level = ((gate_payload or {}).get("gate_level") or "UNKNOWN").upper()

    if gate_level == "RED":
        return {
            "approved": False,
            "reason": "GATE_RED",
            "score": score
        }

    if score < 0.60:
        return {
            "approved": False,
            "reason": "SCORE_LT_0_60",
            "score": score
        }

    if gate_level == "YELLOW" and score < 0.75:
        return {
            "approved": False,
            "reason": "YELLOW_SCORE_LT_0_75",
            "score": score
        }

    return {
        "approved": True,
        "reason": "APPROVED",
        "score": score
    }


# -------------------------------------------------------------------
# DB INIT
# -------------------------------------------------------------------
def init_db():
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            symbol TEXT NOT NULL,
            side TEXT,
            payload_json TEXT,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS signal_acks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signal_id INTEGER NOT NULL,
            symbol TEXT NOT NULL,
            account TEXT NOT NULL,
            magic TEXT,
            ack_utc TEXT NOT NULL,
            UNIQUE(signal_id, account, magic)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT,
            magic TEXT,
            symbol TEXT,
            ea_name TEXT,
            version TEXT,
            last_seen_utc TEXT NOT NULL,
            status TEXT,
            comment TEXT
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT,
            magic TEXT,
            symbol TEXT,
            side TEXT,
            ticket TEXT,
            volume REAL,
            entry_price REAL,
            exit_price REAL,
            sl REAL,
            tp REAL,
            pnl REAL,
            pnl_currency TEXT,
            commission REAL,
            swap REAL,
            risk_amount REAL,
            r_multiple REAL,
            strategy TEXT,
            deal_time_utc TEXT NOT NULL,
            created_utc TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT,
            magic TEXT,
            symbol TEXT,
            event_type TEXT,
            level TEXT,
            message TEXT,
            value REAL,
            created_utc TEXT NOT NULL
        )
        """)

        conn.commit()
        conn.close()


init_db()


# -------------------------------------------------------------------
# MODELS
# -------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class UserResponse(BaseModel):
    username: str


class TVSignalIn(BaseModel):
    key: Optional[str] = None
    symbol: str
    side: Optional[str] = None
    action: Optional[str] = None
    score: Optional[float] = 1.0
    payload: Optional[Dict[str, Any]] = None


class AckIn(BaseModel):
    symbol: str
    updated_utc: str
    account: str
    magic: Optional[str] = None


class HeartbeatPing(BaseModel):
    key: Optional[str] = None
    symbol: str
    account: str
    magic: Optional[str] = None
    ea_name: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = "alive"
    comment: Optional[str] = None


class DealIn(BaseModel):
    account: Optional[str] = None
    magic: Optional[str] = None
    symbol: str
    side: Optional[str] = None
    ticket: Optional[str] = None
    volume: Optional[float] = None
    entry_price: Optional[float] = None
    exit_price: Optional[float] = None
    sl: Optional[float] = None
    tp: Optional[float] = None
    pnl: Optional[float] = None
    pnl_currency: Optional[str] = "USD"
    commission: Optional[float] = 0.0
    swap: Optional[float] = 0.0
    risk_amount: Optional[float] = None
    r_multiple: Optional[float] = None
    strategy: Optional[str] = None
    deal_time_utc: Optional[str] = None


class RiskIn(BaseModel):
    account: Optional[str] = None
    magic: Optional[str] = None
    symbol: str
    event_type: str
    level: Optional[str] = None
    message: Optional[str] = None
    value: Optional[float] = None


# -------------------------------------------------------------------
# BASIC ROUTES
# -------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "ok": True,
        "service": "Signal Agent API",
        "version": "6.4.0",
        "server_time_utc": utc_iso()
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "time": utc_iso()
    }


# -------------------------------------------------------------------
# AUTH ROUTES
# -------------------------------------------------------------------
@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    username = data.username.strip()
    password = data.password.strip()

    if username != APP_USERNAME or password != APP_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token({"sub": username})
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@app.get("/me", response_model=UserResponse)
def me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}


# -------------------------------------------------------------------
# SIGNAL ROUTES
# -------------------------------------------------------------------
@app.post("/tv")
def tv_signal(
    data: TVSignalIn,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key")
):
    provided_key = x_api_key or data.key
    if provided_key != TV_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    symbol = data.symbol.strip().upper()
    side = normalize_side(data.side or data.action)

    if side not in ("BUY", "SELL"):
        raise HTTPException(status_code=422, detail="side/action must be BUY or SELL")

    payload_dict = data.payload or {}
    payload_dict["score"] = safe_float(data.score, 1.0)

    payload_json = json.dumps(payload_dict, ensure_ascii=False)
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO signals(symbol, side, payload_json, created_utc, updated_utc, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
        """, (symbol, side, payload_json, now, now))

        signal_id = cur.lastrowid
        conn.commit()
        conn.close()

    return {
        "ok": True,
        "signal_id": signal_id,
        "symbol": symbol,
        "side": side,
        "score": payload_dict["score"],
        "created_utc": now
    }


@app.post("/ack")
def ack_signal(data: AckIn):
    symbol = data.symbol.strip().upper()
    account = data.account.strip()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        SELECT *
        FROM signals
        WHERE symbol = ?
          AND updated_utc = ?
          AND status = 'pending'
        ORDER BY id DESC
        LIMIT 1
        """, (symbol, data.updated_utc))

        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Signal not found")

        signal_id = row["id"]

        cur.execute("""
        INSERT OR IGNORE INTO signal_acks(signal_id, symbol, account, magic, ack_utc)
        VALUES (?, ?, ?, ?, ?)
        """, (signal_id, symbol, account, data.magic, utc_iso()))

        conn.commit()
        conn.close()

    return {
        "ok": True,
        "signal_id": signal_id,
        "symbol": symbol
