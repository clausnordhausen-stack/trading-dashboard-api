from fastapi import FastAPI, HTTPException, Query, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Dict, List
from jose import jwt, JWTError
from openai import OpenAI
from functools import lru_cache
import os
import sqlite3
import threading
import json

app = FastAPI(title="Signal Agent API", version="11.1.0")

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
MASTER_EMAIL = os.getenv("MASTER_EMAIL", APP_USERNAME)
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", APP_PASSWORD)

DEMO_CUSTOMER_EMAIL = os.getenv("DEMO_CUSTOMER_EMAIL", "customer@claus.digital")
DEMO_CUSTOMER_PASSWORD = os.getenv("DEMO_CUSTOMER_PASSWORD", "Customer123!")
DEMO_CUSTOMER_CODE = os.getenv("DEMO_CUSTOMER_CODE", "CUS-1001")
DEMO_CUSTOMER_NAME = os.getenv("DEMO_CUSTOMER_NAME", "Demo Customer")

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

SIGNAL_TTL_SEC = int(os.getenv("SIGNAL_TTL_SEC", "300"))

RISK_ENGINE_ENABLED = os.getenv("RISK_ENGINE_ENABLED", "true").lower() == "true"
DAILY_LOSS_CAP_USD = float(os.getenv("DAILY_LOSS_CAP_USD", "250.0"))
DAILY_R_CAP = float(os.getenv("DAILY_R_CAP", "-5.0"))
DAILY_MAX_TRADES = int(os.getenv("DAILY_MAX_TRADES", "10"))
RISK_ENGINE_BLOCK_ON_BREACH = os.getenv("RISK_ENGINE_BLOCK_ON_BREACH", "true").lower() == "true"

EXECUTION_MODE = os.getenv("EXECUTION_MODE", "dynamic").strip().lower()
SCORE_TO_RISK_ENABLED = os.getenv("SCORE_TO_RISK_ENABLED", "true").lower() == "true"
SCORE_LOW_THRESHOLD = float(os.getenv("SCORE_LOW_THRESHOLD", "0.6"))
SCORE_HIGH_THRESHOLD = float(os.getenv("SCORE_HIGH_THRESHOLD", "0.85"))
RISK_MULTIPLIER_LOW = float(os.getenv("RISK_MULTIPLIER_LOW", "0.5"))
RISK_MULTIPLIER_NORMAL = float(os.getenv("RISK_MULTIPLIER_NORMAL", "1.0"))
RISK_MULTIPLIER_HIGH = float(os.getenv("RISK_MULTIPLIER_HIGH", "1.5"))

AUTHORIZED_CONSUMERS_STRICT = os.getenv("AUTHORIZED_CONSUMERS_STRICT", "false").lower() == "true"

# OpenAI
OPENAI_ENABLED = os.getenv("OPENAI_ENABLED", "false").lower() == "true"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4").strip()

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


def app_token_guard(x_app_token: Optional[str] = Header(default=None, alias=APP_TOKEN_HEADER)):
    if APP_TOKEN and x_app_token != APP_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid app token")
    return True


def normalize_side(value: Optional[str]) -> str:
    s = (value or "").strip().upper()
    if s == "LONG":
        s = "BUY"
    elif s == "SHORT":
        s = "SELL"
    return s


def get_runtime_controls(symbol: Optional[str] = None) -> Dict[str, Any]:
    return {
        "paused": DEFAULT_PAUSED,
        "allow_new_entries": DEFAULT_ALLOW_NEW_ENTRIES,
        "risk_multiplier": DEFAULT_RISK_MULTIPLIER,
        "symbol": symbol.upper() if symbol else None,
        "source": "default_env"
    }


def ensure_column_exists(table_name: str, column_name: str, column_sql: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    cols = cur.fetchall()
    existing = {c["name"] for c in cols}
    if column_name not in existing:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")
        conn.commit()
    conn.close()


def load_signal_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = {}
    try:
        payload = json.loads(row.get("payload_json") or "{}")
    except Exception:
        payload = {}
    return payload


def get_signal_row_by_id(signal_id: int) -> Optional[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM signals WHERE id = ?", (signal_id,))
        row = cur.fetchone()
        conn.close()
    if row:
        row["payload"] = load_signal_payload(row)
    return row


def dt_or_none(value: Optional[str]) -> Optional[str]:
    dt = parse_dt(value)
    return utc_iso(dt) if dt else None


@lru_cache(maxsize=1)
def get_openai_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    return OpenAI(api_key=api_key)


def extract_response_text(resp: Any) -> str:
    try:
        output_text = getattr(resp, "output_text", None)
        if output_text:
            return output_text.strip()
    except Exception:
        pass

    try:
        output = getattr(resp, "output", None) or []
        parts: List[str] = []
        for item in output:
            contents = getattr(item, "content", None) or []
            for c in contents:
                text_value = getattr(c, "text", None)
                if text_value:
                    parts.append(text_value)
        return "\n".join(parts).strip()
    except Exception:
        return ""


def safe_json_loads(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        return {}


# -------------------------------------------------------------------
# AUTH / USER HELPERS
# -------------------------------------------------------------------
def get_user_by_login(identifier: str) -> Optional[Dict[str, Any]]:
    identifier = identifier.strip()
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM users
            WHERE lower(email) = lower(?) OR lower(username) = lower(?)
            LIMIT 1
            """,
            (identifier, identifier),
        )
        row = cur.fetchone()
        conn.close()
    return row


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
    return row


def get_customer_by_id(customer_id: int) -> Optional[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        row = cur.fetchone()
        conn.close()
    return row


def get_customer_accounts(customer_id: int) -> List[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM customer_accounts
            WHERE customer_id = ?
            ORDER BY id ASC
            """,
            (customer_id,),
        )
        rows = cur.fetchall()
        conn.close()
    return rows


def get_customer_strategies(customer_id: int) -> List[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM customer_strategies
            WHERE customer_id = ?
            ORDER BY sort_order ASC, id ASC
            """,
            (customer_id,),
        )
        rows = cur.fetchall()
        conn.close()
    return rows


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    user_id_raw = payload.get("sub")
    if not user_id_raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    try:
        user_id = int(user_id_raw)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    if safe_int(user.get("is_active"), 0) != 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User inactive"
        )

    return user


def require_master(current_user: dict = Depends(get_current_user)):
    if (current_user.get("role") or "").lower() != "master":
        raise HTTPException(status_code=403, detail="Master access required")
    return current_user


def compute_customer_access(customer: Dict[str, Any]) -> Dict[str, Any]:
    access_end = parse_dt(customer.get("access_end_at"))
    grace_until = parse_dt(customer.get("grace_until"))

    access_status_db = (customer.get("access_status") or "active").lower()
    trading_status_db = (customer.get("trading_status") or "enabled").lower()
    subscription_status = (customer.get("subscription_status") or "active").lower()

    now = now_utc()
    effective_access_status = access_status_db
    effective_trading_status = trading_status_db

    if access_status_db == "paused" or subscription_status == "paused":
        effective_access_status = "paused"
        effective_trading_status = "disabled"
    elif access_end and now > access_end:
        if grace_until and now <= grace_until:
            effective_access_status = "grace"
        else:
            effective_access_status = "expired"
        effective_trading_status = "disabled"
    elif subscription_status in ("expired", "canceled"):
        effective_access_status = "expired"
        effective_trading_status = "disabled"
    elif trading_status_db != "enabled":
        effective_trading_status = "disabled"
    else:
        effective_trading_status = "enabled"
        if access_status_db not in ("active", "grace", "expired", "paused"):
            effective_access_status = "active"

    return {
        "access_start_at": dt_or_none(customer.get("access_start_at")),
        "access_end_at": dt_or_none(customer.get("access_end_at")),
        "grace_until": dt_or_none(customer.get("grace_until")),
        "access_status": effective_access_status,
        "trading_status": effective_trading_status,
        "subscription_status": subscription_status,
        "risk_profile": customer.get("risk_profile") or "balanced",
    }


def build_me_payload(user: Dict[str, Any]) -> Dict[str, Any]:
    role = (user.get("role") or "").lower()

    base = {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "role": role,
        "is_active": bool(safe_int(user.get("is_active"), 0)),
        "customer_id": user.get("customer_id"),
    }

    if role == "master":
        return {
            **base,
            "display_name": "Master",
            "customer_code": None,
            "access_start_at": None,
            "access_end_at": None,
            "grace_until": None,
            "access_status": "active",
            "trading_status": "enabled",
            "subscription_status": "active",
            "risk_profile": "dynamic",
            "accounts": [],
            "strategies": [],
        }

    customer_id = user.get("customer_id")
    if not customer_id:
        return {
            **base,
            "display_name": user.get("email") or user.get("username") or "Customer",
            "customer_code": None,
            "access_start_at": None,
            "access_end_at": None,
            "grace_until": None,
            "access_status": "expired",
            "trading_status": "disabled",
            "subscription_status": "expired",
            "risk_profile": "balanced",
            "accounts": [],
            "strategies": [],
        }

    customer = get_customer_by_id(int(customer_id))
    if not customer:
        return {
            **base,
            "display_name": user.get("email") or user.get("username") or "Customer",
            "customer_code": None,
            "access_start_at": None,
            "access_end_at": None,
            "grace_until": None,
            "access_status": "expired",
            "trading_status": "disabled",
            "subscription_status": "expired",
            "risk_profile": "balanced",
            "accounts": [],
            "strategies": [],
        }

    access = compute_customer_access(customer)

    return {
        **base,
        "display_name": customer.get("display_name") or user.get("email") or "Customer",
        "customer_code": customer.get("code"),
        **access,
        "accounts": get_customer_accounts(int(customer_id)),
        "strategies": get_customer_strategies(int(customer_id)),
    }


# -------------------------------------------------------------------
# SIGNAL FILTER
# -------------------------------------------------------------------
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


def expire_old_signals_and_deliveries():
    cutoff_dt = now_utc() - timedelta(seconds=SIGNAL_TTL_SEC)
    cutoff_iso = utc_iso(cutoff_dt)

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        UPDATE signal_deliveries
        SET delivery_status = 'expired',
            expire_utc = COALESCE(expire_utc, ?),
            updated_utc = ?
        WHERE delivery_status IN ('pending', 'delivered')
          AND created_utc < ?
        """, (utc_iso(), utc_iso(), cutoff_iso))

        cur.execute("""
        UPDATE signals
        SET status = CASE
            WHEN NOT EXISTS (
                SELECT 1
                FROM signal_deliveries d
                WHERE d.signal_id = signals.id
                  AND d.delivery_status IN ('pending', 'delivered', 'acked')
            ) THEN 'closed'
            ELSE status
        END
        WHERE status IN ('pending', 'distributed')
        """)

        cur.execute("""
        UPDATE signals
        SET status = 'expired'
        WHERE status IN ('pending', 'distributed')
          AND created_utc < ?
          AND NOT EXISTS (
              SELECT 1
              FROM signal_deliveries d
              WHERE d.signal_id = signals.id
                AND d.delivery_status IN ('pending', 'delivered', 'acked')
          )
        """, (cutoff_iso,))

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
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            email TEXT,
            access_start_at TEXT,
            access_end_at TEXT,
            access_status TEXT NOT NULL DEFAULT 'active',
            trading_status TEXT NOT NULL DEFAULT 'enabled',
            subscription_status TEXT NOT NULL DEFAULT 'active',
            grace_until TEXT,
            risk_profile TEXT NOT NULL DEFAULT 'balanced',
            notes TEXT,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            customer_id INTEGER,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS customer_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            account_label TEXT NOT NULL,
            broker_name TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS customer_strategies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            account_number TEXT,
            symbol TEXT NOT NULL,
            display_name TEXT NOT NULL,
            magic TEXT NOT NULL,
            strategy_code TEXT,
            risk_tier TEXT NOT NULL DEFAULT 'medium',
            enabled INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 999,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS access_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            actor_user_id INTEGER,
            action_type TEXT NOT NULL,
            action_message TEXT NOT NULL,
            payload_json TEXT,
            created_utc TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id),
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        )
        """)

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

        cur.execute("""
        CREATE TABLE IF NOT EXISTS authorized_consumers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL,
            magic TEXT NOT NULL,
            symbol TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            owner_name TEXT,
            notes TEXT,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            UNIQUE(account, magic, symbol)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS signal_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signal_id INTEGER NOT NULL,
            account TEXT NOT NULL,
            magic TEXT NOT NULL,
            symbol TEXT NOT NULL,
            delivery_status TEXT NOT NULL DEFAULT 'pending',
            first_seen_utc TEXT,
            ack_utc TEXT,
            filled_utc TEXT,
            expire_utc TEXT,
            updated_utc TEXT NOT NULL,
            created_utc TEXT NOT NULL,
            ticket TEXT,
            error_message TEXT,
            UNIQUE(signal_id, account, magic, symbol)
        )
        """)

        conn.commit()
        conn.close()

    ensure_column_exists("deals", "signal_id", "signal_id INTEGER")
    ensure_column_exists("signal_acks", "delivery_id", "delivery_id INTEGER")
    ensure_column_exists("heartbeats", "owner_name", "owner_name TEXT")
    ensure_column_exists("users", "username", "username TEXT")
    ensure_column_exists("users", "email", "email TEXT")
    ensure_column_exists("users", "customer_id", "customer_id INTEGER")
    ensure_column_exists("customers", "subscription_status", "subscription_status TEXT NOT NULL DEFAULT 'active'")
    ensure_column_exists("customers", "grace_until", "grace_until TEXT")
    ensure_column_exists("customers", "risk_profile", "risk_profile TEXT NOT NULL DEFAULT 'balanced'")
    ensure_column_exists("customers", "notes", "notes TEXT")

    seed_auth_data()


def seed_auth_data():
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id FROM users
            WHERE lower(email) = lower(?) OR lower(username) = lower(?)
            LIMIT 1
            """,
            (MASTER_EMAIL, MASTER_EMAIL),
        )
        existing_master = cur.fetchone()

        if not existing_master:
            cur.execute(
                """
                INSERT INTO users(username, email, password, role, is_active, customer_id, created_utc, updated_utc)
                VALUES (?, ?, ?, 'master', 1, NULL, ?, ?)
                """,
                (MASTER_EMAIL, MASTER_EMAIL, MASTER_PASSWORD, now, now),
            )

        cur.execute("SELECT id FROM customers WHERE code = ?", (DEMO_CUSTOMER_CODE,))
        customer = cur.fetchone()

        if not customer:
            access_start = utc_iso(now_utc() - timedelta(days=7))
            access_end = utc_iso(now_utc() + timedelta(days=30))

            cur.execute(
                """
                INSERT INTO customers(
                    code, display_name, email, access_start_at, access_end_at,
                    access_status, trading_status, subscription_status, grace_until,
                    risk_profile, notes, created_utc, updated_utc
                )
                VALUES (?, ?, ?, ?, ?, 'active', 'enabled', 'active', NULL, 'balanced', ?, ?, ?)
                """,
                (
                    DEMO_CUSTOMER_CODE,
                    DEMO_CUSTOMER_NAME,
                    DEMO_CUSTOMER_EMAIL,
                    access_start,
                    access_end,
                    "Seeded demo customer",
                    now,
                    now,
                ),
            )
            customer_id = cur.lastrowid

            cur.execute(
                """
                INSERT OR IGNORE INTO users(username, email, password, role, is_active, customer_id, created_utc, updated_utc)
                VALUES (?, ?, ?, 'customer', 1, ?, ?, ?)
                """,
                (DEMO_CUSTOMER_EMAIL, DEMO_CUSTOMER_EMAIL, DEMO_CUSTOMER_PASSWORD, customer_id, now, now),
            )

            cur.execute(
                """
                INSERT INTO customer_accounts(customer_id, account_number, account_label, broker_name, enabled, created_utc, updated_utc)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (customer_id, "195333", "Main Account", "Demo Broker", now, now),
            )

            cur.execute(
                """
                INSERT INTO customer_strategies(customer_id, account_number, symbol, display_name, magic, strategy_code, risk_tier, enabled, sort_order, created_utc, updated_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (customer_id, "195333", "XAUUSD", "Gold", "777", "xau_core", "medium", 1, now, now),
            )
            cur.execute(
                """
                INSERT INTO customer_strategies(customer_id, account_number, symbol, display_name, magic, strategy_code, risk_tier, enabled, sort_order, created_utc, updated_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (customer_id, "195333", "BTCUSD", "Bitcoin", "62001", "btc_core", "high", 2, now, now),
            )

            cur.execute(
                """
                INSERT INTO access_audits(customer_id, actor_user_id, action_type, action_message, payload_json, created_utc)
                VALUES (?, NULL, 'seed', 'Demo customer created', NULL, ?)
                """,
                (customer_id, now),
            )
        else:
            customer_id = customer["id"]
            cur.execute(
                """
                INSERT OR IGNORE INTO users(username, email, password, role, is_active, customer_id, created_utc, updated_utc)
                VALUES (?, ?, ?, 'customer', 1, ?, ?, ?)
                """,
                (DEMO_CUSTOMER_EMAIL, DEMO_CUSTOMER_EMAIL, DEMO_CUSTOMER_PASSWORD, customer_id, now, now),
            )

        conn.commit()
        conn.close()


init_db()

# -------------------------------------------------------------------
# MODELS
# -------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


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
    ticket: Optional[str] = None


class HeartbeatPing(BaseModel):
    key: Optional[str] = None
    symbol: str
    account: str
    magic: Optional[str] = None
    ea_name: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = "alive"
    comment: Optional[str] = None
    owner_name: Optional[str] = None


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
    signal_id: Optional[int] = None


class RiskIn(BaseModel):
    account: Optional[str] = None
    magic: Optional[str] = None
    symbol: str
    event_type: str
    level: Optional[str] = None
    message: Optional[str] = None
    value: Optional[float] = None


class ConsumerUpsertIn(BaseModel):
    account: str
    magic: str
    symbol: str
    enabled: bool = True
    owner_name: Optional[str] = None
    notes: Optional[str] = None


class AIDecisionIn(BaseModel):
    symbol: str
    side: str
    score: Optional[float] = 1.0
    account: Optional[str] = None
    magic: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class AIDecisionOut(BaseModel):
    ok: bool
    ai_enabled: bool
    symbol: str
    side: str
    model: Optional[str] = None
    gate_level: Optional[str] = None
    allow_new_entries: Optional[bool] = None
    risk_level: Optional[str] = None
    approved: bool
    confidence: float
    risk_mode: str
    action: str
    reason: str
    raw_text: Optional[str] = None


# -------------------------------------------------------------------
# AUTH ROUTES
# -------------------------------------------------------------------
@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    identifier = (data.email or data.username or "").strip()
    password = data.password.strip()

    if not identifier:
        raise HTTPException(status_code=422, detail="email or username required")

    user = get_user_by_login(identifier)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if safe_int(user.get("is_active"), 0) != 1:
        raise HTTPException(status_code=403, detail="User inactive")

    if (user.get("password") or "") != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        {
            "sub": str(user["id"]),
            "email": user.get("email"),
            "role": user.get("role"),
        }
    )
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    return build_me_payload(current_user)


@app.post("/ai/decision", response_model=AIDecisionOut)
def ai_decision(data: AIDecisionIn):
    symbol = data.symbol.strip().upper()
    side = normalize_side(data.side)
    score = safe_float(data.score, 1.0)

    if side not in ("BUY", "SELL"):
        raise HTTPException(status_code=422, detail="side must be BUY or SELL")

    gate = gate_combo(symbol=symbol, account=data.account, magic=data.magic)
    risk_engine = compute_risk_engine(symbol=symbol, account=data.account, magic=data.magic)

    fallback_approved = bool(gate.get("allow_new_entries", False)) and score >= 0.60
    fallback_action = "ALLOW" if fallback_approved else "BLOCK"

    if not OPENAI_ENABLED:
        return {
            "ok": True,
            "ai_enabled": False,
            "symbol": symbol,
            "side": side,
            "model": None,
            "gate_level": gate.get("gate_level"),
            "allow_new_entries": gate.get("allow_new_entries"),
            "risk_level": risk_engine.get("risk_level"),
            "approved": fallback_approved,
            "confidence": round(max(0.0, min(1.0, score)), 4),
            "risk_mode": "fallback",
            "action": fallback_action,
            "reason": "OpenAI disabled, fallback decision used",
            "raw_text": None,
        }

    system_prompt = """
You are a trading decision support engine.
You do NOT place trades.
You evaluate whether a signal should be allowed, reduced, or blocked.

Return ONLY valid JSON with these exact keys:
approved
confidence
risk_mode
action
reason

Rules:
- approved must be true or false
- confidence must be a number from 0.0 to 1.0
- risk_mode must be one of: block, reduced, normal, aggressive
- action must be one of: BLOCK, ALLOW, REDUCE
- reason must be a short clear sentence
- If gate_level is RED or allow_new_entries is false, action should normally be BLOCK
- If risk_level is RED, action should normally be BLOCK
- Consider score, gate state, risk state, and context together
"""

    user_payload = {
        "symbol": symbol,
        "side": side,
        "score": score,
        "gate": gate,
        "risk_engine": risk_engine,
        "context": data.context or {},
    }

    try:
        client = get_openai_client()
        resp = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
        )

        raw_text = extract_response_text(resp)
        parsed = safe_json_loads(raw_text)

        approved = bool(parsed.get("approved", fallback_approved))
        confidence = safe_float(parsed.get("confidence"), score)
        risk_mode = str(parsed.get("risk_mode", "normal")).strip().lower()
        action = str(parsed.get("action", fallback_action)).strip().upper()
        reason = str(parsed.get("reason", "AI decision generated")).strip()

        if risk_mode not in ("block", "reduced", "normal", "aggressive"):
            risk_mode = "normal"

        if action not in ("BLOCK", "ALLOW", "REDUCE"):
            action = fallback_action

        return {
            "ok": True,
            "ai_enabled": True,
            "symbol": symbol,
            "side": side,
            "model": OPENAI_MODEL,
            "gate_level": gate.get("gate_level"),
            "allow_new_entries": gate.get("allow_new_entries"),
            "risk_level": risk_engine.get("risk_level"),
            "approved": approved,
            "confidence": round(max(0.0, min(1.0, confidence)), 4),
            "risk_mode": risk_mode,
            "action": action,
            "reason": reason,
            "raw_text": raw_text or None,
        }

    except Exception as e:
        return {
            "ok": True,
            "ai_enabled": True,
            "symbol": symbol,
            "side": side,
            "model": OPENAI_MODEL,
            "gate_level": gate.get("gate_level"),
            "allow_new_entries": gate.get("allow_new_entries"),
            "risk_level": risk_engine.get("risk_level"),
            "approved": fallback_approved,
            "confidence": round(max(0.0, min(1.0, score)), 4),
            "risk_mode": "fallback",
            "action": fallback_action,
            "reason": f"AI fallback used: {str(e)}",
            "raw_text": None,
        }


@app.get("/master/customers")
def master_customers(current_user: dict = Depends(require_master)):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM customers
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        conn.close()

    items = []
    for customer in rows:
        customer_id = int(customer["id"])
        access = compute_customer_access(customer)

        with DB_LOCK:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, username, email, role, is_active
                FROM users
                WHERE customer_id = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (customer_id,),
            )
            user = cur.fetchone()
            conn.close()

        items.append({
            "id": customer_id,
            "code": customer.get("code"),
            "display_name": customer.get("display_name"),
            "email": customer.get("email"),
            "notes": customer.get("notes"),
            "user": user,
            **access,
            "accounts": get_customer_accounts(customer_id),
            "strategies": get_customer_strategies(customer_id),
        })

    return {
        "ok": True,
        "count": len(items),
        "items": items,
    }


# -------------------------------------------------------------------
# BASIC ROUTES
# -------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "ok": True,
        "service": "Signal Agent API",
        "version": "11.1.0",
        "server_time_utc": utc_iso(),
        "openai_enabled": OPENAI_ENABLED,
        "openai_model": OPENAI_MODEL,
    }


@app.get("/health")
def health():
    expire_old_signals_and_deliveries()
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "time": utc_iso()
    }


# -------------------------------------------------------------------
# AUTHORIZED CONSUMERS
# -------------------------------------------------------------------
def list_authorized_consumers(symbol: Optional[str] = None) -> List[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        if symbol:
            cur.execute("""
            SELECT *
            FROM authorized_consumers
            WHERE symbol = ?
            ORDER BY account, magic, symbol
            """, (symbol.upper(),))
        else:
            cur.execute("""
            SELECT *
            FROM authorized_consumers
            ORDER BY symbol, account, magic
            """)
        rows = cur.fetchall()
        conn.close()
    return rows


def get_live_heartbeat_consumers(symbol: str) -> List[Dict[str, Any]]:
    symbol = symbol.upper()
    cutoff = now_utc() - timedelta(seconds=HEARTBEAT_TIMEOUT_SEC)

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        SELECT *
        FROM heartbeats
        WHERE symbol = ?
        ORDER BY id DESC
        LIMIT 500
        """, (symbol,))
        rows = cur.fetchall()
        conn.close()

    latest_map = {}
    for r in rows:
        key = (r.get("account") or "", r.get("magic") or "", r.get("symbol") or "")
        if key not in latest_map:
            latest_map[key] = r

    consumers = []
    for _, r in latest_map.items():
        last_seen = parse_dt(r.get("last_seen_utc"))
        if not last_seen or last_seen < cutoff:
            continue
        account = (r.get("account") or "").strip()
        magic = (r.get("magic") or "").strip()
        hb_symbol = (r.get("symbol") or "").strip().upper()
        if account and magic and hb_symbol == symbol:
            consumers.append({
                "account": account,
                "magic": magic,
                "symbol": hb_symbol,
                "enabled": 1,
                "owner_name": r.get("owner_name"),
                "notes": "heartbeat_fallback"
            })

    unique_map = {}
    for c in consumers:
        key = (c["account"], c["magic"], c["symbol"])
        if key not in unique_map:
            unique_map[key] = c

    return list(unique_map.values())


def resolve_target_consumers(symbol: str) -> List[Dict[str, Any]]:
    symbol = symbol.upper()
    authorized = [
        r for r in list_authorized_consumers(symbol=symbol)
        if safe_int(r.get("enabled"), 0) == 1
    ]

    if authorized:
        return authorized

    if AUTHORIZED_CONSUMERS_STRICT:
        return []

    return get_live_heartbeat_consumers(symbol)


@app.get("/consumers")
def consumers(symbol: Optional[str] = Query(default=None)):
    items = list_authorized_consumers(symbol=symbol)
    return {
        "ok": True,
        "count": len(items),
        "items": items
    }


@app.post("/consumers/upsert")
def consumers_upsert(
    data: ConsumerUpsertIn,
    _: bool = Depends(app_token_guard)
):
    symbol = data.symbol.strip().upper()
    account = data.account.strip()
    magic = data.magic.strip()

    if not symbol or not account or not magic:
        raise HTTPException(status_code=422, detail="account, magic, symbol required")

    now = utc_iso()
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO authorized_consumers(account, magic, symbol, enabled, owner_name, notes, created_utc, updated_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(account, magic, symbol) DO UPDATE SET
            enabled = excluded.enabled,
            owner_name = excluded.owner_name,
            notes = excluded.notes,
            updated_utc = excluded.updated_utc
        """, (
            account,
            magic,
            symbol,
            1 if data.enabled else 0,
            data.owner_name,
            data.notes,
            now,
            now
        ))
        conn.commit()
        conn.close()

    return {
        "ok": True,
        "account": account,
        "magic": magic,
        "symbol": symbol,
        "enabled": data.enabled
    }


# -------------------------------------------------------------------
# HEARTBEAT
# -------------------------------------------------------------------
@app.post("/hb")
def heartbeat(data: HeartbeatPing):
    if data.key and data.key != TV_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid key")

    now = utc_iso()
    symbol = data.symbol.upper()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO heartbeats(account, magic, symbol, ea_name, version, last_seen_utc, status, comment, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.account,
            data.magic,
            symbol,
            data.ea_name,
            data.version,
            now,
            data.status,
            data.comment,
            data.owner_name
        ))

        conn.commit()
        conn.close()

    return {"ok": True, "server_time_utc": now}


@app.post("/heartbeat")
def heartbeat_alias(data: HeartbeatPing):
    return heartbeat(data)


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
            LIMIT 500
            """, (symbol_norm,))
        else:
            cur.execute("""
            SELECT * FROM heartbeats
            ORDER BY id DESC
            LIMIT 1000
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
            "owner_name": r.get("owner_name"),
        })

    return {
        "ok": True,
        "timeout_sec": HEARTBEAT_TIMEOUT_SEC,
        "connected_count": connected_count,
        "items": result
    }


# -------------------------------------------------------------------
# SIGNAL DISTRIBUTION
# -------------------------------------------------------------------
def create_signal_deliveries(signal_id: int, symbol: str) -> List[Dict[str, Any]]:
    symbol = symbol.upper()
    targets = resolve_target_consumers(symbol)
    now = utc_iso()

    created = []

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        for t in targets:
            account = (t.get("account") or "").strip()
            magic = (t.get("magic") or "").strip()
            if not account or not magic:
                continue

            cur.execute("""
            INSERT OR IGNORE INTO signal_deliveries(
                signal_id, account, magic, symbol, delivery_status,
                first_seen_utc, ack_utc, filled_utc, expire_utc,
                updated_utc, created_utc, ticket, error_message
            )
            VALUES (?, ?, ?, ?, 'pending', NULL, NULL, NULL, NULL, ?, ?, NULL, NULL)
            """, (
                signal_id,
                account,
                magic,
                symbol,
                now,
                now
            ))

            created.append({
                "signal_id": signal_id,
                "account": account,
                "magic": magic,
                "symbol": symbol
            })

        cur.execute("""
        UPDATE signals
        SET status = ?
        WHERE id = ?
        """, ("distributed" if created else "pending", signal_id))

        conn.commit()
        conn.close()

    return created


@app.post("/tv")
def tv_signal(
    data: TVSignalIn,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key")
):
    expire_old_signals_and_deliveries()

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

    deliveries = create_signal_deliveries(signal_id=signal_id, symbol=symbol)

    return {
        "ok": True,
        "signal_id": signal_id,
        "symbol": symbol,
        "side": side,
        "created_utc": now,
        "deliveries_created": len(deliveries),
        "deliveries": deliveries
    }


def get_latest_delivery_for_consumer(symbol: str, account: str, magic: Optional[str]) -> Optional[Dict[str, Any]]:
    magic = magic or ""
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        SELECT d.*, s.side, s.payload_json, s.updated_utc AS signal_updated_utc, s.created_utc AS signal_created_utc, s.status AS signal_status
        FROM signal_deliveries d
        JOIN signals s ON s.id = d.signal_id
        WHERE d.symbol = ?
          AND d.account = ?
          AND d.magic = ?
          AND d.delivery_status IN ('pending', 'delivered')
        ORDER BY d.id DESC
        LIMIT 1
        """, (symbol, account, magic))
        row = cur.fetchone()
        conn.close()

    if row:
        row["payload"] = load_signal_payload(row)
    return row


@app.get("/latest")
def latest_signal(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: Optional[str] = Query(default=None),
):
    expire_old_signals_and_deliveries()

    symbol = symbol.strip().upper()
    account = account.strip()
    magic = (magic or "").strip()

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

    delivery = get_latest_delivery_for_consumer(symbol=symbol, account=account, magic=magic)

    if not delivery:
        return {
            "ok": True,
            "has_signal": False,
            "symbol": symbol,
            "blocked": False,
            "controls": controls,
            "gate": gate_payload
        }

    signal_created = parse_dt(delivery.get("signal_created_utc"))
    if signal_created:
        age_sec = int((now_utc() - signal_created).total_seconds())
        if age_sec > SIGNAL_TTL_SEC:
            with DB_LOCK:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("""
                UPDATE signal_deliveries
                SET delivery_status = 'expired',
                    expire_utc = ?,
                    updated_utc = ?
                WHERE id = ?
                """, (utc_iso(), utc_iso(), delivery["id"]))
                conn.commit()
                conn.close()

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

    signal_row = {
        "id": delivery["signal_id"],
        "symbol": symbol,
        "side": delivery.get("side"),
        "payload": delivery.get("payload", {}),
        "created_utc": delivery.get("signal_created_utc"),
        "updated_utc": delivery.get("signal_updated_utc"),
        "status": delivery.get("signal_status"),
    }

    filter_result = signal_passes_filter(signal_row, gate_payload)

    if not filter_result["approved"]:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": True,
            "reason": filter_result["reason"],
            "filter": filter_result,
            "symbol": symbol,
            "controls": controls,
            "gate": gate_payload,
            "delivery": {
                "delivery_id": delivery["id"],
                "signal_id": delivery["signal_id"],
                "delivery_status": delivery["delivery_status"],
            }
        }

    execution_engine = compute_execution_engine(signal_row, gate_payload)

    if not execution_engine["approved"]:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": True,
            "reason": "EXECUTION_ENGINE_BLOCK",
            "execution_engine": execution_engine,
            "symbol": symbol,
            "controls": controls,
            "gate": gate_payload,
            "delivery": {
                "delivery_id": delivery["id"],
                "signal_id": delivery["signal_id"],
                "delivery_status": delivery["delivery_status"],
            }
        }

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        UPDATE signal_deliveries
        SET delivery_status = CASE
                WHEN delivery_status = 'pending' THEN 'delivered'
                ELSE delivery_status
            END,
            first_seen_utc = COALESCE(first_seen_utc, ?),
            updated_utc = ?
        WHERE id = ?
        """, (utc_iso(), utc_iso(), delivery["id"]))
        conn.commit()
        conn.close()

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
        "delivery": {
            "delivery_id": delivery["id"],
            "signal_id": delivery["signal_id"],
            "delivery_status": delivery["delivery_status"],
            "first_seen_utc": delivery.get("first_seen_utc"),
            "ack_utc": delivery.get("ack_utc"),
        },
        "signal": signal_row
    }


@app.post("/ack")
def ack_signal(data: AckIn):
    expire_old_signals_and_deliveries()

    symbol = data.symbol.strip().upper()
    account = data.account.strip()
    magic = (data.magic or "").strip()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        SELECT d.*, s.updated_utc AS signal_updated_utc
        FROM signal_deliveries d
        JOIN signals s ON s.id = d.signal_id
        WHERE d.symbol = ?
          AND d.account = ?
          AND d.magic = ?
          AND s.updated_utc = ?
          AND d.delivery_status IN ('pending', 'delivered')
        ORDER BY d.id DESC
        LIMIT 1
        """, (symbol, account, magic, data.updated_utc))

        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Delivery not found")

        delivery_id = row["id"]
        signal_id = row["signal_id"]
        ack_time = utc_iso()

        cur.execute("""
        UPDATE signal_deliveries
        SET delivery_status = 'acked',
            ack_utc = ?,
            ticket = COALESCE(?, ticket),
            updated_utc = ?
        WHERE id = ?
        """, (ack_time, data.ticket, ack_time, delivery_id))

        cur.execute("""
        INSERT OR IGNORE INTO signal_acks(signal_id, symbol, account, magic, ack_utc, delivery_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (signal_id, symbol, account, magic, ack_time, delivery_id))

        cur.execute("""
        UPDATE signals
        SET status = CASE
            WHEN EXISTS (
                SELECT 1
                FROM signal_deliveries d
                WHERE d.signal_id = signals.id
                  AND d.delivery_status IN ('pending', 'delivered', 'acked')
            ) THEN 'distributed'
            ELSE 'closed'
        END
        WHERE id = ?
        """, (signal_id,))

        conn.commit()
        conn.close()

    return {
        "ok": True,
        "signal_id": signal_id,
        "delivery_id": delivery_id,
        "symbol": symbol,
        "account": account,
        "magic": magic
    }


# -------------------------------------------------------------------
# DEALS + RISKS
# -------------------------------------------------------------------
def resolve_signal_id_for_deal(account: Optional[str], magic: Optional[str], symbol: str, explicit_signal_id: Optional[int]) -> Optional[int]:
    if explicit_signal_id:
        return explicit_signal_id

    account = (account or "").strip()
    magic = (magic or "").strip()
    symbol = symbol.upper()

    if not account or not magic:
        return None

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        SELECT *
        FROM signal_deliveries
        WHERE account = ?
          AND magic = ?
          AND symbol = ?
          AND delivery_status = 'acked'
        ORDER BY ack_utc DESC, id DESC
        LIMIT 1
        """, (account, magic, symbol))
        row = cur.fetchone()
        conn.close()

    if row:
        return row["signal_id"]
    return None


@app.post("/deal")
def post_deal(data: DealIn):
    deal_time = data.deal_time_utc or utc_iso()
    symbol = data.symbol.upper()
    resolved_signal_id = resolve_signal_id_for_deal(
        account=data.account,
        magic=data.magic,
        symbol=symbol,
        explicit_signal_id=data.signal_id
    )

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO deals(
            account, magic, symbol, side, ticket, volume,
            entry_price, exit_price, sl, tp,
            pnl, pnl_currency, commission, swap,
            risk_amount, r_multiple, strategy,
            deal_time_utc, created_utc, signal_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.account,
            data.magic,
            symbol,
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
            utc_iso(),
            resolved_signal_id
        ))

        if resolved_signal_id and data.account and data.magic:
            cur.execute("""
            UPDATE signal_deliveries
            SET delivery_status = 'filled',
                filled_utc = ?,
                ticket = COALESCE(?, ticket),
                updated_utc = ?
            WHERE signal_id = ?
              AND account = ?
              AND magic = ?
              AND symbol = ?
              AND delivery_status IN ('acked', 'delivered', 'pending')
            """, (
                utc_iso(),
                data.ticket,
                utc_iso(),
                resolved_signal_id,
                data.account,
                data.magic,
                symbol
            ))

            cur.execute("""
            UPDATE signals
            SET status = CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM signal_deliveries d
                    WHERE d.signal_id = signals.id
                      AND d.delivery_status IN ('pending', 'delivered', 'acked')
                ) THEN 'distributed'
                ELSE 'closed'
            END
            WHERE id = ?
            """, (resolved_signal_id,))

        conn.commit()
        conn.close()

    return {"ok": True, "signal_id": resolved_signal_id}


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

    return list(reversed(rows))


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
        running += safe_float(r.get("pnl"), 0.0)
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
# RISK ENGINE
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
# EXECUTION ENGINE
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
    dummy_signal = {"payload": {"score": score}}
    dummy_gate = {"gate_level": gate_level.upper()}

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
    if paused or not risk_allow:
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
    expire_old_signals_and_deliveries()

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
        heartbeat_payload = heartbeat_status(symbol=symbol) if symbol else heartbeat_status()
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
# DEBUG ENDPOINTS
# -------------------------------------------------------------------
@app.get("/debug/state")
def debug_state(symbol: str = Query(...)):
    expire_old_signals_and_deliveries()
    symbol = symbol.strip().upper()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        SELECT *
        FROM signals
        WHERE symbol = ?
        ORDER BY id DESC
        LIMIT 10
        """, (symbol,))
        signals = cur.fetchall()

        cur.execute("""
        SELECT *
        FROM signal_deliveries
        WHERE symbol = ?
        ORDER BY id DESC
        LIMIT 100
        """, (symbol,))
        deliveries = cur.fetchall()

        conn.close()

    for s in signals:
        s["payload"] = load_signal_payload(s)

    return {
        "ok": True,
        "symbol": symbol,
        "signals": signals,
        "deliveries": deliveries
    }


@app.get("/debug/recent_acks")
def debug_recent_acks(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        query = "SELECT * FROM signal_acks WHERE 1=1"
        params = []

        if symbol:
            query += " AND symbol = ?"
            params.append(symbol.upper())
        if account:
            query += " AND account = ?"
            params.append(account)
        if magic:
            query += " AND magic = ?"
            params.append(magic)

        query += " ORDER BY id DESC LIMIT 100"
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

    return {
        "ok": True,
        "count": len(rows),
        "items": rows
    }


@app.get("/debug/delivery_status")
def debug_delivery_status(signal_id: int = Query(...)):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT * FROM signals WHERE id = ?", (signal_id,))
        signal_row = cur.fetchone()

        cur.execute("""
        SELECT *
        FROM signal_deliveries
        WHERE signal_id = ?
        ORDER BY symbol, account, magic
        """, (signal_id,))
        deliveries = cur.fetchall()

        conn.close()

    if not signal_row:
        raise HTTPException(status_code=404, detail="signal not found")

    signal_row["payload"] = load_signal_payload(signal_row)

    return {
        "ok": True,
        "signal": signal_row,
        "delivery_count": len(deliveries),
        "deliveries": deliveries
    }


@app.get("/debug/pending_by_consumer")
def debug_pending_by_consumer(
    account: str = Query(...),
    magic: str = Query(...),
    symbol: str = Query(...)
):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        SELECT d.*, s.side, s.payload_json, s.created_utc AS signal_created_utc, s.updated_utc AS signal_updated_utc
        FROM signal_deliveries d
        JOIN signals s ON s.id = d.signal_id
        WHERE d.account = ?
          AND d.magic = ?
          AND d.symbol = ?
          AND d.delivery_status IN ('pending', 'delivered', 'acked')
        ORDER BY d.id DESC
        LIMIT 50
        """, (account, magic, symbol.upper()))
        rows = cur.fetchall()
        conn.close()

    for r in rows:
        try:
            r["payload"] = json.loads(r.get("payload_json") or "{}")
        except Exception:
            r["payload"] = {}

    return {
        "ok": True,
        "count": len(rows),
        "items": rows
    }
