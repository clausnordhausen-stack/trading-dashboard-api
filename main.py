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

app = FastAPI(title="Signal Agent API", version="9.0.0")

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

APP_TOKEN = os.getenv("APP_TOKEN", "").strip()
APP_TOKEN_HEADER = os.getenv("APP_TOKEN_HEADER", "X-APP-TOKEN").strip() or "X-APP-TOKEN"

TV_API_KEY = os.getenv("TV_API_KEY", SECRET_KEY)

DEFAULT_ALLOW_NEW_ENTRIES = os.getenv("DEFAULT_ALLOW_NEW_ENTRIES", "true").lower() == "true"
DEFAULT_RISK_MULTIPLIER = float(os.getenv("DEFAULT_RISK_MULTIPLIER", "1.0"))
DEFAULT_PAUSED = os.getenv("DEFAULT_PAUSED", "false").lower() == "true"

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

# Phase 7
SIGNAL_TTL_SEC = int(os.getenv("SIGNAL_TTL_SEC", "300"))

# Phase 8 - Risk Engine
RISK_ENGINE_ENABLED = os.getenv("RISK_ENGINE_ENABLED", "true").lower() == "true"
DAILY_LOSS_CAP_USD = float(os.getenv("DAILY_LOSS_CAP_USD", "250.0"))
DAILY_R_CAP = float(os.getenv("DAILY_R_CAP", "-5.0"))
DAILY_MAX_TRADES = int(os.getenv("DAILY_MAX_TRADES", "10"))
RISK_ENGINE_BLOCK_ON_BREACH = os.getenv("RISK_ENGINE_BLOCK_ON_BREACH", "true").lower() == "true"

# Phase 9 - Execution Intelligence
EXECUTION_MODE = os.getenv("EXECUTION_MODE", "dynamic").strip().lower()
SCORE_TO_RISK_ENABLED = os.getenv("SCORE_TO_RISK_ENABLED", "true").lower() == "true"
SCORE_LOW_THRESHOLD = float(os.getenv("SCORE_LOW_THRESHOLD", "0.6"))
SCORE_HIGH_THRESHOLD = float(os.getenv("SCORE_HIGH_THRESHOLD", "0.85"))
RISK_MULTIPLIER_LOW = float(os.getenv("RISK_MULTIPLIER_LOW", "0.5"))
RISK_MULTIPLIER_NORMAL = float(os.getenv("RISK_MULTIPLIER_NORMAL", "1.0"))
RISK_MULTIPLIER_HIGH = float(os.getenv("RISK_MULTIPLIER_HIGH", "1.5"))

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


def utc_day_start(dt: Optional[datetime] = None) -> datetime:
    if dt is None:
        dt = now_utc()
    dt = dt.astimezone(timezone.utc)
    return datetime(dt.year, dt.month, dt.day, 0, 0, 0, tzinfo=timezone.utc)


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


def expire_old_signals():
    cutoff = utc_iso(now_utc() - timedelta(seconds=SIGNAL_TTL_SEC))
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        UPDATE signals
        SET status = 'expired'
        WHERE status = 'pending'
          AND created_utc < ?
        """, (cutoff,))
        conn.commit()
        conn.close()


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
        "version": "9.0.0",
        "server_time_utc": utc_iso()
    }


@app.get("/health")
def health():
    expire_old_signals()
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
    expire_old_signals()

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
        "created_utc": now
    }


@app.post("/ack")
def ack_signal(data: AckIn):
    expire_old_signals()

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
        "symbol": symbol,
        "account": account,
        "magic": data.magic
    }


@app.post("/hb")
def heartbeat(data: HeartbeatPing):
    if data.key and data.key != TV_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid key")

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO heartbeats(account, magic, symbol, ea_name, version, last_seen_utc, status, comment)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.account,
            data.magic,
            data.symbol.upper(),
            data.ea_name,
            data.version,
            utc_iso(),
            data.status,
            data.comment
        ))

        conn.commit()
        conn.close()

    return {"ok": True, "server_time_utc": utc_iso()}


@app.get("/status/heartbeat")
def heartbeat_status(symbol: Optional[str] = Query(default=None)):
    symbol_norm = symbol.strip().upper() if symbol else None
    cutoff = now_utc() - timedelta(seconds=HEARTBEAT_TIMEOUT_SEC)

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        if symbol_norm:
            cur.execute("""
            SELECT * FROM heartbeats
            WHERE symbol = ?
            ORDER BY id DESC
            LIMIT 200
            """, (symbol_norm,))
        else:
            cur.execute("""
            SELECT * FROM heartbeats
            ORDER BY id DESC
            LIMIT 500
            """)

        rows = cur.fetchall()
        conn.close()

    latest_map = {}
    for r in rows:
        key = f"{r.get('account','')}|{r.get('magic','')}|{r.get('symbol','')}"
        if key not in latest_map:
            latest_map[key] = r

    result = []
    connected_count = 0

    for _, r in latest_map.items():
        last_seen = parse_dt(r["last_seen_utc"])
        connected = bool(last_seen and last_seen >= cutoff)
        if connected:
            connected_count += 1

        result.append({
            "account": r.get("account"),
            "magic": r.get("magic"),
            "symbol": r.get("symbol"),
            "ea_name": r.get("ea_name"),
            "version": r.get("version"),
            "last_seen_utc": r.get("last_seen_utc"),
            "connected": connected,
            "status": r.get("status"),
            "comment": r.get("comment"),
        })

    return {
        "ok": True,
        "timeout_sec": HEARTBEAT_TIMEOUT_SEC,
        "connected_count": connected_count,
        "items": result
    }


# -------------------------------------------------------------------
# DEALS + RISKS
# -------------------------------------------------------------------
@app.post("/deal")
def post_deal(data: DealIn):
    deal_time = data.deal_time_utc or utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO deals(
            account, magic, symbol, side, ticket, volume,
            entry_price, exit_price, sl, tp,
            pnl, pnl_currency, commission, swap,
            risk_amount, r_multiple, strategy,
            deal_time_utc, created_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.account,
            data.magic,
            data.symbol.upper(),
            data.side,
            data.ticket,
            data.volume,
            data.entry_price,
            data.exit_price,
            data.sl,
            data.tp,
            data.pnl,
            data.pnl_currency,
            data.commission,
            data.swap,
            data.risk_amount,
            data.r_multiple,
            data.strategy,
            deal_time,
            utc_iso()
        ))

        conn.commit()
        conn.close()

    return {"ok": True}


@app.post("/risk")
def post_risk(data: RiskIn):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO risks(account, magic, symbol, event_type, level, message, value, created_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.account,
            data.magic,
            data.symbol.upper(),
            data.event_type,
            data.level,
            data.message,
            data.value,
            utc_iso()
        ))

        conn.commit()
        conn.close()

    return {"ok": True}


# -------------------------------------------------------------------
# KPI CORE
# -------------------------------------------------------------------
def get_deals_filtered(
    symbol: Optional[str] = None,
    account: Optional[str] = None,
    magic: Optional[str] = None,
    lookback_days: int = DEFAULT_KPI_LOOKBACK_DAYS,
    limit_trades: int = DEFAULT_KPI_LIMIT_TRADES,
):
    dt_from = now_utc() - timedelta(days=lookback_days)

    query = """
    SELECT *
    FROM deals
    WHERE deal_time_utc >= ?
    """
    params = [utc_iso(dt_from)]

    if symbol:
        query += " AND symbol = ?"
        params.append(symbol.upper())

    if account:
        query += " AND account = ?"
        params.append(account)

    if magic:
        query += " AND magic = ?"
        params.append(magic)

    query += " ORDER BY deal_time_utc DESC LIMIT ?"
    params.append(limit_trades)

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

    rows = list(reversed(rows))
    return rows


def get_deals_today(
    symbol: Optional[str] = None,
    account: Optional[str] = None,
    magic: Optional[str] = None,
):
    dt_from = utc_day_start()

    query = """
    SELECT *
    FROM deals
    WHERE deal_time_utc >= ?
    """
    params = [utc_iso(dt_from)]

    if symbol:
        query += " AND symbol = ?"
        params.append(symbol.upper())

    if account:
        query += " AND account = ?"
        params.append(account)

    if magic:
        query += " AND magic = ?"
        params.append(magic)

    query += " ORDER BY deal_time_utc ASC"

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

    return rows


def calc_equity_curve_from_pnl(rows: List[Dict[str, Any]]) -> List[float]:
    curve = [0.0]
    running = 0.0
    for r in rows:
        pnl = safe_float(r.get("pnl"), 0.0)
        running += pnl
        curve.append(running)
    return curve


def calc_max_drawdown_abs(curve: List[float]) -> float:
    peak = -10**18
    max_dd = 0.0
    for x in curve:
        if x > peak:
            peak = x
        dd = peak - x
        if dd > max_dd:
            max_dd = dd
    return max_dd


def calc_max_drawdown_pct(curve: List[float]) -> float:
    peak = None
    max_dd_pct = 0.0
    for x in curve:
        if peak is None or x > peak:
            peak = x
        if peak and peak > 0:
            dd_pct = ((peak - x) / peak) * 100.0
            if dd_pct > max_dd_pct:
                max_dd_pct = dd_pct
    return max_dd_pct


def calc_loss_streak(rows: List[Dict[str, Any]]) -> int:
    streak = 0
    max_streak = 0
    for r in rows:
        pnl = safe_float(r.get("pnl"), 0.0)
        if pnl < 0:
            streak += 1
            max_streak = max(max_streak, streak)
        else:
            streak = 0
    return max_streak


def calc_current_loss_streak(rows: List[Dict[str, Any]]) -> int:
    streak = 0
    for r in reversed(rows):
        pnl = safe_float(r.get("pnl"), 0.0)
        if pnl < 0:
            streak += 1
        else:
            break
    return streak


def summarize_kpis(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_trades = len(rows)
    wins = 0
    losses = 0
    breakeven = 0

    gross_profit = 0.0
    gross_loss = 0.0
    net_pnl = 0.0
    total_r = 0.0

    for r in rows:
        pnl = safe_float(r.get("pnl"), 0.0)
        r_mult = safe_float(r.get("r_multiple"), 0.0)

        net_pnl += pnl
        total_r += r_mult

        if pnl > 0:
            wins += 1
            gross_profit += pnl
        elif pnl < 0:
            losses += 1
            gross_loss += abs(pnl)
        else:
            breakeven += 1

    winrate = (wins / total_trades * 100.0) if total_trades > 0 else 0.0
    avg_pnl = (net_pnl / total_trades) if total_trades > 0 else 0.0
    avg_r = (total_r / total_trades) if total_trades > 0 else 0.0
    profit_factor = (gross_profit / gross_loss) if gross_loss > 0 else (999.0 if gross_profit > 0 else 0.0)

    curve = calc_equity_curve_from_pnl(rows)
    max_dd_abs = calc_max_drawdown_abs(curve)
    max_dd_pct = calc_max_drawdown_pct(curve)
    max_loss_streak = calc_loss_streak(rows)
    current_loss_streak = calc_current_loss_streak(rows)

    last_trade_time = rows[-1]["deal_time_utc"] if total_trades > 0 else None

    return {
        "total_trades": total_trades,
        "wins": wins,
        "losses": losses,
        "breakeven": breakeven,
        "winrate_pct": round(winrate, 2),
        "gross_profit": round(gross_profit, 2),
        "gross_loss": round(gross_loss, 2),
        "net_pnl": round(net_pnl, 2),
        "avg_pnl": round(avg_pnl, 2),
        "sum_r": round(total_r, 2),
        "avg_r": round(avg_r, 2),
        "profit_factor": round(profit_factor, 2),
        "max_drawdown_abs": round(max_dd_abs, 2),
        "max_drawdown_pct": round(max_dd_pct, 2),
        "max_loss_streak": max_loss_streak,
        "current_loss_streak": current_loss_streak,
        "last_trade_time_utc": last_trade_time,
    }


def auto_gate_from_kpis(kpi: Dict[str, Any]) -> Dict[str, Any]:
    if not AUTO_GATE_ENABLED:
        return {
            "gate_level": DEFAULT_GATE_LEVEL,
            "allow_new_entries": DEFAULT_GATE_LEVEL != "RED",
            "risk_multiplier": 1.0 if DEFAULT_GATE_LEVEL == "GREEN" else 0.5 if DEFAULT_GATE_LEVEL == "YELLOW" else 0.0,
            "reasons": ["AUTO_GATE_DISABLED"]
        }

    reasons_red = []
    reasons_yellow = []

    dd_pct = safe_float(kpi.get("max_drawdown_pct"))
    cur_loss_streak = safe_int(kpi.get("current_loss_streak"))
    sum_r = safe_float(kpi.get("sum_r"))
    winrate = safe_float(kpi.get("winrate_pct"))
    total_trades = safe_int(kpi.get("total_trades"))

    if dd_pct >= RED_DD_PCT:
        reasons_red.append(f"MAX_DD_PCT>={RED_DD_PCT}")

    if cur_loss_streak >= RED_LOSS_STREAK:
        reasons_red.append(f"LOSS_STREAK>={RED_LOSS_STREAK}")

    if sum_r <= RED_R_SUM:
        reasons_red.append(f"SUM_R<={RED_R_SUM}")

    if total_trades >= 5 and winrate < RED_WINRATE_MIN:
        reasons_red.append(f"WINRATE<{RED_WINRATE_MIN}")

    if reasons_red:
        return {
            "gate_level": "RED",
            "allow_new_entries": False,
            "risk_multiplier": 0.0,
            "reasons": reasons_red
        }

    if dd_pct >= YELLOW_DD_PCT:
        reasons_yellow.append(f"MAX_DD_PCT>={YELLOW_DD_PCT}")

    if cur_loss_streak >= YELLOW_LOSS_STREAK:
        reasons_yellow.append(f"LOSS_STREAK>={YELLOW_LOSS_STREAK}")

    if sum_r <= YELLOW_R_SUM:
        reasons_yellow.append(f"SUM_R<={YELLOW_R_SUM}")

    if total_trades >= 5 and winrate < YELLOW_WINRATE_MIN:
        reasons_yellow.append(f"WINRATE<{YELLOW_WINRATE_MIN}")

    if reasons_yellow:
        return {
            "gate_level": "YELLOW",
            "allow_new_entries": True,
            "risk_multiplier": 0.5,
            "reasons": reasons_yellow
        }

    return {
        "gate_level": "GREEN",
        "allow_new_entries": True,
        "risk_multiplier": 1.0,
        "reasons": ["NORMAL"]
    }


def compute_auto_gate(
    symbol: Optional[str] = None,
    account: Optional[str] = None,
    magic: Optional[str] = None,
    lookback_days: int = DEFAULT_KPI_LOOKBACK_DAYS,
    limit_trades: int = DEFAULT_KPI_LIMIT_TRADES,
) -> Dict[str, Any]:
    rows = get_deals_filtered(
        symbol=symbol,
        account=account,
        magic=magic,
        lookback_days=lookback_days,
        limit_trades=limit_trades
    )

    kpis = summarize_kpis(rows)
    gate = auto_gate_from_kpis(kpis)

    return {
        "kpis": kpis,
        "gate": gate
    }


# -------------------------------------------------------------------
# PHASE 8 - RISK ENGINE
# -------------------------------------------------------------------
def compute_risk_engine(
    symbol: Optional[str] = None,
    account: Optional[str] = None,
    magic: Optional[str] = None,
) -> Dict[str, Any]:
    rows = get_deals_today(symbol=symbol, account=account, magic=magic)

    daily_pnl = 0.0
    daily_r = 0.0
    total_trades = len(rows)

    for r in rows:
        daily_pnl += safe_float(r.get("pnl"), 0.0)
        daily_r += safe_float(r.get("r_multiple"), 0.0)

    reasons = []
    allow_new_entries = True
    level = "GREEN"

    if not RISK_ENGINE_ENABLED:
        return {
            "enabled": False,
            "allow_new_entries": True,
            "risk_level": "OFF",
            "daily_pnl": round(daily_pnl, 2),
            "daily_r": round(daily_r, 2),
            "daily_trades": total_trades,
            "limits": {
                "daily_loss_cap_usd": DAILY_LOSS_CAP_USD,
                "daily_r_cap": DAILY_R_CAP,
                "daily_max_trades": DAILY_MAX_TRADES,
            },
            "reasons": ["RISK_ENGINE_DISABLED"]
        }

    if daily_pnl <= -abs(DAILY_LOSS_CAP_USD):
        allow_new_entries = False
        level = "RED"
        reasons.append(f"DAILY_LOSS_CAP_REACHED<={-abs(DAILY_LOSS_CAP_USD)}")

    if daily_r <= DAILY_R_CAP:
        allow_new_entries = False
        level = "RED"
        reasons.append(f"DAILY_R_CAP_REACHED<={DAILY_R_CAP}")

    if DAILY_MAX_TRADES > 0 and total_trades >= DAILY_MAX_TRADES:
        allow_new_entries = False
        level = "RED"
        reasons.append(f"DAILY_MAX_TRADES_REACHED>={DAILY_MAX_TRADES}")

    if not reasons:
        reasons.append("NORMAL")

    return {
        "enabled": True,
        "allow_new_entries": allow_new_entries if RISK_ENGINE_BLOCK_ON_BREACH else True,
        "risk_level": level,
        "daily_pnl": round(daily_pnl, 2),
        "daily_r": round(daily_r, 2),
        "daily_trades": total_trades,
        "limits": {
            "daily_loss_cap_usd": DAILY_LOSS_CAP_USD,
            "daily_r_cap": DAILY_R_CAP,
            "daily_max_trades": DAILY_MAX_TRADES,
        },
        "reasons": reasons
    }


# -------------------------------------------------------------------
# PHASE 9 - EXECUTION ENGINE
# -------------------------------------------------------------------
def compute_execution_engine(
    signal_row: Optional[Dict[str, Any]] = None,
    gate_payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = (signal_row or {}).get("payload", {}) or {}
    score = safe_float(payload.get("score"), 1.0)

    gate_level = ((gate_payload or {}).get("gate_level") or "UNKNOWN").upper()

    mode = EXECUTION_MODE
    reasons = []
    risk_multiplier = RISK_MULTIPLIER_NORMAL
    priority = "NORMAL"

    if gate_level == "RED":
        return {
            "mode": mode,
            "score_to_risk_enabled": SCORE_TO_RISK_ENABLED,
            "score": score,
            "priority": "BLOCKED",
            "risk_multiplier": 0.0,
            "approved": False,
            "reasons": ["GATE_RED"]
        }

    if not SCORE_TO_RISK_ENABLED:
        return {
            "mode": mode,
            "score_to_risk_enabled": False,
            "score": score,
            "priority": "NORMAL",
            "risk_multiplier": RISK_MULTIPLIER_NORMAL,
            "approved": True,
            "reasons": ["SCORE_TO_RISK_DISABLED"]
        }

    if mode == "safe":
        risk_multiplier = min(RISK_MULTIPLIER_LOW, RISK_MULTIPLIER_NORMAL)
        priority = "LOW"
        reasons.append("MODE_SAFE")

    elif mode == "normal":
        risk_multiplier = RISK_MULTIPLIER_NORMAL
        priority = "NORMAL"
        reasons.append("MODE_NORMAL")

    elif mode == "aggressive":
        if score >= SCORE_HIGH_THRESHOLD:
            risk_multiplier = RISK_MULTIPLIER_HIGH
            priority = "HIGH"
            reasons.append("MODE_AGGRESSIVE_HIGH_SCORE")
        else:
            risk_multiplier = RISK_MULTIPLIER_NORMAL
            priority = "NORMAL"
            reasons.append("MODE_AGGRESSIVE_NORMAL_SCORE")

    else:
        if score < SCORE_LOW_THRESHOLD:
            risk_multiplier = RISK_MULTIPLIER_LOW
            priority = "LOW"
            reasons.append(f"SCORE<{SCORE_LOW_THRESHOLD}")
        elif score >= SCORE_HIGH_THRESHOLD:
            risk_multiplier = RISK_MULTIPLIER_HIGH
            priority = "HIGH"
            reasons.append(f"SCORE>={SCORE_HIGH_THRESHOLD}")
        else:
            risk_multiplier = RISK_MULTIPLIER_NORMAL
            priority = "NORMAL"
            reasons.append("MID_SCORE_RANGE")

        reasons.append("MODE_DYNAMIC")

    if gate_level == "YELLOW":
        risk_multiplier = min(risk_multiplier, RISK_MULTIPLIER_NORMAL)
        reasons.append("YELLOW_GATE_CAP")

    return {
        "mode": mode,
        "score_to_risk_enabled": SCORE_TO_RISK_ENABLED,
        "score": round(score, 4),
        "priority": priority,
        "risk_multiplier": round(risk_multiplier, 4),
        "approved": True,
        "reasons": reasons
    }


# -------------------------------------------------------------------
# CONTROLS + GATES
# -------------------------------------------------------------------
@app.get("/controls/effective")
def controls_effective(
    symbol: Optional[str] = Query(default=None),
    _: bool = Depends(app_token_guard)
):
    return {
        "ok": True,
        "controls": get_runtime_controls(symbol)
    }


@app.get("/status/gate_auto")
def gate_auto(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
    lookback_days: int = Query(default=DEFAULT_KPI_LOOKBACK_DAYS),
    limit_trades: int = Query(default=DEFAULT_KPI_LIMIT_TRADES),
):
    result = compute_auto_gate(
        symbol=symbol,
        account=account,
        magic=magic,
        lookback_days=lookback_days,
        limit_trades=limit_trades
    )

    return {
        "ok": True,
        "filters": {
            "symbol": symbol.upper() if symbol else None,
            "account": account,
            "magic": magic,
            "lookback_days": lookback_days,
            "limit_trades": limit_trades,
        },
        "kpis": result["kpis"],
        "gate": result["gate"]
    }


@app.get("/status/risk_engine")
def status_risk_engine(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
):
    result = compute_risk_engine(symbol=symbol, account=account, magic=magic)
    return {
        "ok": True,
        "filters": {
            "symbol": symbol.upper() if symbol else None,
            "account": account,
            "magic": magic,
        },
        "risk_engine": result
    }


@app.get("/status/execution_engine")
def status_execution_engine(
    score: float = Query(default=1.0),
    gate_level: str = Query(default="GREEN"),
):
    dummy_signal = {
        "payload": {
            "score": score
        }
    }
    dummy_gate = {
        "gate_level": gate_level.upper()
    }

    result = compute_execution_engine(dummy_signal, dummy_gate)

    return {
        "ok": True,
        "input": {
            "score": score,
            "gate_level": gate_level.upper()
        },
        "execution_engine": result
    }


@app.get("/status/gate_combo")
def gate_combo(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
):
    controls = get_runtime_controls(symbol)
    auto_payload = compute_auto_gate(symbol=symbol, account=account, magic=magic)
    auto_gate = auto_payload["gate"]
    risk_engine = compute_risk_engine(symbol=symbol, account=account, magic=magic)

    paused = bool(controls["paused"])
    controls_allow = bool(controls["allow_new_entries"])
    auto_allow = bool(auto_gate["allow_new_entries"])
    risk_allow = bool(risk_engine["allow_new_entries"])

    allow_new_entries = (not paused) and controls_allow and auto_allow and risk_allow
    final_risk_multiplier = safe_float(controls["risk_multiplier"], 1.0) * safe_float(auto_gate["risk_multiplier"], 1.0)

    gate_level = auto_gate["gate_level"]
    if paused:
        gate_level = "RED"
    if not risk_allow:
        gate_level = "RED"

    reasons = []
    if paused:
        reasons.append("PAUSED")
    if not controls_allow:
        reasons.append("CONTROL_BLOCK")
    reasons.extend(auto_gate.get("reasons", []))
    if not risk_allow:
        reasons.extend(risk_engine.get("reasons", []))

    return {
        "ok": True,
        "symbol": symbol.upper() if symbol else None,
        "gate_level": gate_level,
        "allow_new_entries": allow_new_entries,
        "risk_multiplier": round(final_risk_multiplier, 4),
        "paused": paused,
        "controls": controls,
        "auto_gate": auto_gate,
        "risk_engine": risk_engine,
        "reasons": reasons
    }


# -------------------------------------------------------------------
# KPI ENDPOINTS
# -------------------------------------------------------------------
@app.get("/kpis/rolling")
def rolling_kpis(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
    lookback_days: int = Query(default=DEFAULT_KPI_LOOKBACK_DAYS),
    limit_trades: int = Query(default=DEFAULT_KPI_LIMIT_TRADES),
):
    rows = get_deals_filtered(
        symbol=symbol,
        account=account,
        magic=magic,
        lookback_days=lookback_days,
        limit_trades=limit_trades
    )

    kpis = summarize_kpis(rows)

    return {
        "ok": True,
        "filters": {
            "symbol": symbol.upper() if symbol else None,
            "account": account,
            "magic": magic,
            "lookback_days": lookback_days,
            "limit_trades": limit_trades,
        },
        "kpis": kpis
    }


@app.get("/status/system_overview")
def system_overview(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
    lookback_days: int = Query(default=DEFAULT_KPI_LOOKBACK_DAYS),
    limit_trades: int = Query(default=DEFAULT_KPI_LIMIT_TRADES),
):
    expire_old_signals()

    rows = get_deals_filtered(
        symbol=symbol,
        account=account,
        magic=magic,
        lookback_days=lookback_days,
        limit_trades=limit_trades
    )

    kpis = summarize_kpis(rows)
    gate = gate_combo(symbol=symbol, account=account, magic=magic)
    risk_engine = compute_risk_engine(symbol=symbol, account=account, magic=magic)

    heartbeat_payload = {"ok": False, "connected_count": 0, "items": []}
    try:
        if symbol:
            heartbeat_payload = heartbeat_status(symbol=symbol)
        else:
            heartbeat_payload = heartbeat_status()
    except Exception:
        pass

    return {
        "ok": True,
        "server_time_utc": utc_iso(),
        "filters": {
            "symbol": symbol.upper() if symbol else None,
            "account": account,
            "magic": magic,
            "lookback_days": lookback_days,
            "limit_trades": limit_trades,
        },
        "heartbeat": heartbeat_payload,
        "controls": get_runtime_controls(symbol),
        "kpis": kpis,
        "gate": gate,
        "risk_engine": risk_engine
    }


# -------------------------------------------------------------------
# LATEST SIGNAL DELIVERY
# -------------------------------------------------------------------
@app.get("/latest")
def latest_signal(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: Optional[str] = Query(default=None),
):
    expire_old_signals()

    symbol = symbol.strip().upper()
    account = account.strip()

    controls = get_runtime_controls(symbol)
    gate_payload = gate_combo(symbol=symbol, account=account, magic=magic)

    if controls["paused"] or not controls["allow_new_entries"] or not gate_payload["allow_new_entries"]:
        return {
            "ok": True,
            "has_signal": False,
            "symbol": symbol,
            "blocked": True,
            "controls": controls,
            "gate": gate_payload
        }

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        SELECT s.*
        FROM signals s
        WHERE s.symbol = ?
          AND s.status = 'pending'
          AND NOT EXISTS (
              SELECT 1 FROM signal_acks a
              WHERE a.signal_id = s.id
                AND a.account = ?
                AND COALESCE(a.magic, '') = COALESCE(?, '')
          )
        ORDER BY s.id DESC
        LIMIT 1
        """, (symbol, account, magic))

        row = cur.fetchone()
        conn.close()

    if not row:
        return {
            "ok": True,
            "has_signal": False,
            "symbol": symbol,
            "blocked": False,
            "controls": controls,
            "gate": gate_payload
        }

    signal_created = parse_dt(row.get("created_utc"))
    if signal_created:
        age_sec = int((now_utc() - signal_created).total_seconds())
        if age_sec > SIGNAL_TTL_SEC:
            return {
                "ok": True,
                "has_signal": False,
                "blocked": True,
                "reason": "TTL_EXPIRED",
                "ttl_sec": SIGNAL_TTL_SEC,
                "signal_age_sec": age_sec,
                "symbol": symbol,
                "controls": controls,
                "gate": gate_payload
            }

    try:
        row["payload"] = json.loads(row.get("payload_json") or "{}")
    except Exception:
        row["payload"] = {}

    filter_result = signal_passes_filter(row, gate_payload)

    if not filter_result["approved"]:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": True,
            "reason": filter_result["reason"],
            "filter": filter_result,
            "symbol": symbol,
            "controls": controls,
            "gate": gate_payload
        }

    execution_engine = compute_execution_engine(row, gate_payload)

    if not execution_engine["approved"]:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": True,
            "reason": "EXECUTION_ENGINE_BLOCK",
            "execution_engine": execution_engine,
            "symbol": symbol,
            "controls": controls,
            "gate": gate_payload
        }

    effective_risk_multiplier = (
        safe_float(controls["risk_multiplier"], 1.0)
        * safe_float(gate_payload.get("risk_multiplier"), 1.0)
        * safe_float(execution_engine.get("risk_multiplier"), 1.0)
    )

    return {
        "ok": True,
        "has_signal": True,
        "blocked": False,
        "filter": filter_result,
        "execution_engine": execution_engine,
        "effective_risk_multiplier": round(effective_risk_multiplier, 4),
        "symbol": symbol,
        "controls": controls,
        "gate": gate_payload,
        "signal": row
    }
