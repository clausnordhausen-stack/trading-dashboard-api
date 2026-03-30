from fastapi import FastAPI, HTTPException, Query, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Dict, List
from jose import jwt, JWTError
import os
import sqlite3
import threading
import json

app = FastAPI(title="Signal Agent API", version="12.0.0")

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
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

DEFAULT_GATE_LEVEL = os.getenv("DEFAULT_GATE_LEVEL", "GREEN").upper()
HEARTBEAT_TIMEOUT_SEC = int(os.getenv("HEARTBEAT_TIMEOUT_SEC", "90"))

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

# Default seed users
MASTER_EMAIL = os.getenv("MASTER_EMAIL", "master@claus.digital")
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "ChangeMe123!")

FIRST_CUSTOMER_EMAIL = os.getenv("FIRST_CUSTOMER_EMAIL", "claus@claus.digital")
FIRST_CUSTOMER_PASSWORD = os.getenv("FIRST_CUSTOMER_PASSWORD", "Claus123!")
FIRST_CUSTOMER_NAME = os.getenv("FIRST_CUSTOMER_NAME", "Claus Nordhausen")

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


def safe_str(x, default=""):
    if x is None:
        return default
    return str(x).strip()


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
    s = safe_str(value).upper()
    if s == "LONG":
        return "BUY"
    if s == "SHORT":
        return "SELL"
    return s


def load_signal_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = {}
    try:
        payload = json.loads(row.get("payload_json") or "{}")
    except Exception:
        payload = {}
    return payload


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


# -------------------------------------------------------------------
# DB INIT
# -------------------------------------------------------------------
def init_db():
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        # ---------------- USER / CUSTOMER CORE ----------------
        cur.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT NOT NULL,
            access_start_at TEXT,
            access_end_at TEXT,
            access_status TEXT NOT NULL DEFAULT 'active',
            trading_status TEXT NOT NULL DEFAULT 'enabled',
            subscription_status TEXT NOT NULL DEFAULT 'active',
            grace_until TEXT,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            customer_id INTEGER,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS customer_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            broker_name TEXT,
            account_number TEXT NOT NULL,
            account_label TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            UNIQUE(customer_id, account_number)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS customer_strategies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            symbol TEXT NOT NULL,
            strategy_code TEXT NOT NULL,
            strategy_name TEXT NOT NULL,
            magic TEXT NOT NULL,
            risk_tier TEXT NOT NULL DEFAULT 'balanced',
            enabled INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 999,
            base_lot REAL NOT NULL DEFAULT 0.01,
            max_lot REAL NOT NULL DEFAULT 1.0,
            color TEXT NOT NULL DEFAULT '#D4AF37',
            refresh_override_seconds INTEGER,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            UNIQUE(customer_id, account_number, symbol, strategy_code, magic)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            actor_role TEXT,
            target_customer_id INTEGER,
            target_account_number TEXT,
            action_type TEXT NOT NULL,
            message TEXT,
            payload_json TEXT,
            created_utc TEXT NOT NULL
        )
        """)

        # ---------------- TRADING / EXISTING CORE ----------------
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

    seed_initial_data()


def seed_initial_data():
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        # Master user
        cur.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (MASTER_EMAIL,))
        master_user = cur.fetchone()
        if not master_user:
            cur.execute("""
            INSERT INTO users(email, password, role, customer_id, is_active, created_utc, updated_utc)
            VALUES (?, ?, 'master', NULL, 1, ?, ?)
            """, (MASTER_EMAIL, MASTER_PASSWORD, now, now))

        # First customer user
        cur.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (FIRST_CUSTOMER_EMAIL,))
        customer_user = cur.fetchone()

        if not customer_user:
            cur.execute("""
            INSERT INTO customers(
                display_name, access_start_at, access_end_at,
                access_status, trading_status, subscription_status, grace_until,
                created_utc, updated_utc
            )
            VALUES (?, ?, NULL, 'active', 'enabled', 'active', NULL, ?, ?)
            """, (
                FIRST_CUSTOMER_NAME,
                now,
                now,
                now,
            ))
            customer_id = cur.lastrowid

            cur.execute("""
            INSERT INTO users(email, password, role, customer_id, is_active, created_utc, updated_utc)
            VALUES (?, ?, 'customer', ?, 1, ?, ?)
            """, (
                FIRST_CUSTOMER_EMAIL,
                FIRST_CUSTOMER_PASSWORD,
                customer_id,
                now,
                now,
            ))

            seed_accounts = [
                ("TheTradingPit", "504055635", "Claus Nordhausen"),
                ("TheTradingPit", "504047407", "TheTradingPit - Gina Marie Menge"),
                ("TheTradingPit", "504046072", "TheTradingPit - Katja Nordhausen"),
            ]

            for broker_name, account_number, account_label in seed_accounts:
                cur.execute("""
                INSERT OR IGNORE INTO customer_accounts(
                    customer_id, broker_name, account_number, account_label, is_active, created_utc, updated_utc
                )
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """, (customer_id, broker_name, account_number, account_label, now, now))

                cur.execute("""
                INSERT OR IGNORE INTO customer_strategies(
                    customer_id, account_number, symbol, strategy_code, strategy_name, magic,
                    risk_tier, enabled, sort_order, base_lot, max_lot, color,
                    refresh_override_seconds, created_utc, updated_utc
                )
                VALUES (?, ?, 'XAUUSD', 'xau_core', 'Gold', '777',
                        'balanced', 1, 1, 0.01, 1.00, '#D4AF37',
                        NULL, ?, ?)
                """, (customer_id, account_number, now, now))

                cur.execute("""
                INSERT OR IGNORE INTO customer_strategies(
                    customer_id, account_number, symbol, strategy_code, strategy_name, magic,
                    risk_tier, enabled, sort_order, base_lot, max_lot, color,
                    refresh_override_seconds, created_utc, updated_utc
                )
                VALUES (?, ?, 'BTCUSD', 'btc_core', 'Bitcoin', '62001',
                        'balanced', 1, 2, 0.01, 1.00, '#F7931A',
                        NULL, ?, ?)
                """, (customer_id, account_number, now, now))

        conn.commit()
        conn.close()


init_db()

# -------------------------------------------------------------------
# USER HELPERS
# -------------------------------------------------------------------
def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (email,))
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


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    user = get_user_by_id(int(user_id))
    if not user or safe_int(user.get("is_active"), 0) != 1:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User inactive or missing"
        )
    return user


def require_master(current_user: dict = Depends(get_current_user)):
    if safe_str(current_user.get("role")) != "master":
        raise HTTPException(status_code=403, detail="Master role required")
    return current_user


def require_customer(current_user: dict = Depends(get_current_user)):
    if safe_str(current_user.get("role")) != "customer":
        raise HTTPException(status_code=403, detail="Customer role required")
    return current_user


def write_audit_log(
    actor_user_id: Optional[int],
    actor_role: Optional[str],
    action_type: str,
    message: str,
    target_customer_id: Optional[int] = None,
    target_account_number: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO audit_logs(
            actor_user_id, actor_role, target_customer_id, target_account_number,
            action_type, message, payload_json, created_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            actor_user_id,
            actor_role,
            target_customer_id,
            target_account_number,
            action_type,
            message,
            json.dumps(payload or {}, ensure_ascii=False),
            utc_iso(),
        ))
        conn.commit()
        conn.close()


def build_customer_accounts_payload(customer_id: int) -> List[Dict[str, Any]]:
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        SELECT *
        FROM customer_accounts
        WHERE customer_id = ? AND is_active = 1
        ORDER BY account_label, account_number
        """, (customer_id,))
        accounts = cur.fetchall()

        cur.execute("""
        SELECT *
        FROM customer_strategies
        WHERE customer_id = ? AND enabled = 1
        ORDER BY account_number, sort_order, symbol, strategy_name
        """, (customer_id,))
        strategies = cur.fetchall()

        conn.close()

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in strategies:
        grouped.setdefault(row["account_number"], []).append({
            "symbol": row["symbol"],
            "displayName": row["strategy_name"],
            "magic": row["magic"],
            "enabled": bool(row["enabled"]),
            "sortOrder": row["sort_order"],
            "baseLot": row["base_lot"],
            "maxLot": row["max_lot"],
            "color": row["color"],
            "refreshOverrideSeconds": row["refresh_override_seconds"],
            "strategyCode": row["strategy_code"],
            "riskTier": row["risk_tier"],
        })

    result = []
    for account in accounts:
        result.append({
            "accountNumber": account["account_number"],
            "label": account["account_label"],
            "enabled": bool(account["is_active"]),
            "brokerName": account.get("broker_name"),
            "symbols": grouped.get(account["account_number"], []),
        })

    return result


# -------------------------------------------------------------------
# MODELS
# -------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
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


class MasterCustomerCreateIn(BaseModel):
    display_name: str
    email: EmailStr
    password: str
    access_status: str = "active"
    trading_status: str = "enabled"
    subscription_status: str = "active"


class MasterCustomerAccountUpsertIn(BaseModel):
    customer_id: int
    broker_name: Optional[str] = None
    account_number: str
    account_label: str
    is_active: bool = True


class MasterCustomerStrategyUpsertIn(BaseModel):
    customer_id: int
    account_number: str
    symbol: str
    strategy_code: str
    strategy_name: str
    magic: str
    risk_tier: str = "balanced"
    enabled: bool = True
    sort_order: int = 999
    base_lot: float = 0.01
    max_lot: float = 1.0
    color: str = "#D4AF37"
    refresh_override_seconds: Optional[int] = None


class CustomerAccountCreateIn(BaseModel):
    broker_name: Optional[str] = None
    account_number: str
    account_label: str


class CustomerStrategyUpsertIn(BaseModel):
    account_number: str
    symbol: str
    strategy_code: str
    strategy_name: str
    magic: str
    risk_tier: str = "balanced"
    enabled: bool = True
    sort_order: int = 999
    base_lot: float = 0.01
    max_lot: float = 1.0
    color: str = "#D4AF37"
    refresh_override_seconds: Optional[int] = None


# -------------------------------------------------------------------
# AUTH ROUTES
# -------------------------------------------------------------------
@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    user = get_user_by_email(data.email.strip())
    if not user or safe_str(user.get("password")) != data.password.strip():
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token({
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
    })

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    customer = None
    if current_user.get("customer_id"):
        customer = get_customer_by_id(int(current_user["customer_id"]))

    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "role": current_user["role"],
        "is_active": bool(current_user["is_active"]),
        "customer_id": current_user.get("customer_id"),
        "display_name": customer["display_name"] if customer else current_user["email"],
        "access_status": customer["access_status"] if customer else "active",
        "trading_status": customer["trading_status"] if customer else "enabled",
        "subscription_status": customer["subscription_status"] if customer else "active",
        "access_start_at": customer["access_start_at"] if customer else None,
        "access_end_at": customer["access_end_at"] if customer else None,
        "grace_until": customer["grace_until"] if customer else None,
    }


# -------------------------------------------------------------------
# BASIC ROUTES
# -------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "ok": True,
        "service": "Signal Agent API",
        "version": "12.0.0",
        "server_time_utc": utc_iso(),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "time": utc_iso(),
    }


# -------------------------------------------------------------------
# CUSTOMER ROUTES
# -------------------------------------------------------------------
@app.get("/customer/accounts")
def customer_accounts(current_user: dict = Depends(require_customer)):
    customer_id = current_user.get("customer_id")
    if not customer_id:
        raise HTTPException(status_code=404, detail="Customer not linked")

    return {
        "ok": True,
        "items": build_customer_accounts_payload(int(customer_id)),
    }


@app.post("/customer/accounts/create")
def customer_account_create(
    data: CustomerAccountCreateIn,
    current_user: dict = Depends(require_customer),
):
    customer_id = int(current_user["customer_id"])
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT OR IGNORE INTO customer_accounts(
            customer_id, broker_name, account_number, account_label, is_active, created_utc, updated_utc
        )
        VALUES (?, ?, ?, ?, 1, ?, ?)
        """, (
            customer_id,
            data.broker_name,
            data.account_number.strip(),
            data.account_label.strip(),
            now,
            now,
        ))
        conn.commit()
        conn.close()

    write_audit_log(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        target_customer_id=customer_id,
        target_account_number=data.account_number.strip(),
        action_type="customer_account_create",
        message=f"Customer created account {data.account_number.strip()}",
        payload=data.model_dump(),
    )

    return {"ok": True}


@app.post("/customer/strategies/upsert")
def customer_strategy_upsert(
    data: CustomerStrategyUpsertIn,
    current_user: dict = Depends(require_customer),
):
    customer_id = int(current_user["customer_id"])
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO customer_strategies(
            customer_id, account_number, symbol, strategy_code, strategy_name, magic,
            risk_tier, enabled, sort_order, base_lot, max_lot, color,
            refresh_override_seconds, created_utc, updated_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(customer_id, account_number, symbol, strategy_code, magic)
        DO UPDATE SET
            strategy_name = excluded.strategy_name,
            risk_tier = excluded.risk_tier,
            enabled = excluded.enabled,
            sort_order = excluded.sort_order,
            base_lot = excluded.base_lot,
            max_lot = excluded.max_lot,
            color = excluded.color,
            refresh_override_seconds = excluded.refresh_override_seconds,
            updated_utc = excluded.updated_utc
        """, (
            customer_id,
            data.account_number.strip(),
            data.symbol.strip().upper(),
            data.strategy_code.strip(),
            data.strategy_name.strip(),
            data.magic.strip(),
            data.risk_tier.strip(),
            1 if data.enabled else 0,
            data.sort_order,
            data.base_lot,
            data.max_lot,
            data.color.strip(),
            data.refresh_override_seconds,
            now,
            now,
        ))
        conn.commit()
        conn.close()

    write_audit_log(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        target_customer_id=customer_id,
        target_account_number=data.account_number.strip(),
        action_type="customer_strategy_upsert",
        message=f"Customer upserted strategy {data.strategy_code.strip()} on {data.account_number.strip()}",
        payload=data.model_dump(),
    )

    return {"ok": True}


# -------------------------------------------------------------------
# MASTER ROUTES
# -------------------------------------------------------------------
@app.get("/master/customers")
def master_customers(current_user: dict = Depends(require_master)):
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        SELECT c.*, u.email
        FROM customers c
        LEFT JOIN users u ON u.customer_id = c.id AND u.role = 'customer'
        ORDER BY c.display_name
        """)
        rows = cur.fetchall()
        conn.close()

    return {"ok": True, "items": rows}


@app.post("/master/customers/create")
def master_customer_create(
    data: MasterCustomerCreateIn,
    current_user: dict = Depends(require_master),
):
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (data.email.strip(),))
        exists = cur.fetchone()
        if exists:
            conn.close()
            raise HTTPException(status_code=409, detail="Email already exists")

        cur.execute("""
        INSERT INTO customers(
            display_name, access_start_at, access_end_at, access_status,
            trading_status, subscription_status, grace_until, created_utc, updated_utc
        )
        VALUES (?, ?, NULL, ?, ?, ?, NULL, ?, ?)
        """, (
            data.display_name.strip(),
            now,
            data.access_status.strip(),
            data.trading_status.strip(),
            data.subscription_status.strip(),
            now,
            now,
        ))
        customer_id = cur.lastrowid

        cur.execute("""
        INSERT INTO users(email, password, role, customer_id, is_active, created_utc, updated_utc)
        VALUES (?, ?, 'customer', ?, 1, ?, ?)
        """, (
            data.email.strip(),
            data.password.strip(),
            customer_id,
            now,
            now,
        ))

        conn.commit()
        conn.close()

    write_audit_log(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        target_customer_id=customer_id,
        action_type="master_customer_create",
        message=f"Master created customer {data.display_name.strip()}",
        payload=data.model_dump(exclude={"password"}),
    )

    return {"ok": True, "customer_id": customer_id}


@app.post("/master/customer/account/upsert")
def master_customer_account_upsert(
    data: MasterCustomerAccountUpsertIn,
    current_user: dict = Depends(require_master),
):
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO customer_accounts(
            customer_id, broker_name, account_number, account_label, is_active, created_utc, updated_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(customer_id, account_number)
        DO UPDATE SET
            broker_name = excluded.broker_name,
            account_label = excluded.account_label,
            is_active = excluded.is_active,
            updated_utc = excluded.updated_utc
        """, (
            data.customer_id,
            data.broker_name,
            data.account_number.strip(),
            data.account_label.strip(),
            1 if data.is_active else 0,
            now,
            now,
        ))
        conn.commit()
        conn.close()

    write_audit_log(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        target_customer_id=data.customer_id,
        target_account_number=data.account_number.strip(),
        action_type="master_customer_account_upsert",
        message=f"Master upserted account {data.account_number.strip()}",
        payload=data.model_dump(),
    )

    return {"ok": True}


@app.post("/master/customer/strategy/upsert")
def master_customer_strategy_upsert(
    data: MasterCustomerStrategyUpsertIn,
    current_user: dict = Depends(require_master),
):
    now = utc_iso()

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO customer_strategies(
            customer_id, account_number, symbol, strategy_code, strategy_name, magic,
            risk_tier, enabled, sort_order, base_lot, max_lot, color,
            refresh_override_seconds, created_utc, updated_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(customer_id, account_number, symbol, strategy_code, magic)
        DO UPDATE SET
            strategy_name = excluded.strategy_name,
            risk_tier = excluded.risk_tier,
            enabled = excluded.enabled,
            sort_order = excluded.sort_order,
            base_lot = excluded.base_lot,
            max_lot = excluded.max_lot,
            color = excluded.color,
            refresh_override_seconds = excluded.refresh_override_seconds,
            updated_utc = excluded.updated_utc
        """, (
            data.customer_id,
            data.account_number.strip(),
            data.symbol.strip().upper(),
            data.strategy_code.strip(),
            data.strategy_name.strip(),
            data.magic.strip(),
            data.risk_tier.strip(),
            1 if data.enabled else 0,
            data.sort_order,
            data.base_lot,
            data.max_lot,
            data.color.strip(),
            data.refresh_override_seconds,
            now,
            now,
        ))
        conn.commit()
        conn.close()

    write_audit_log(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        target_customer_id=data.customer_id,
        target_account_number=data.account_number.strip(),
        action_type="master_customer_strategy_upsert",
        message=f"Master upserted strategy {data.strategy_code.strip()} on {data.account_number.strip()}",
        payload=data.model_dump(),
    )

    return {"ok": True}


@app.get("/master/customer/{customer_id}/accounts")
def master_customer_accounts(
    customer_id: int,
    current_user: dict = Depends(require_master),
):
    return {
        "ok": True,
        "items": build_customer_accounts_payload(customer_id),
    }


@app.get("/master/audit_logs")
def master_audit_logs(
    target_customer_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100),
    current_user: dict = Depends(require_master),
):
    limit = max(1, min(limit, 500))

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        query = "SELECT * FROM audit_logs WHERE 1=1"
        params: List[Any] = []

        if target_customer_id is not None:
            query += " AND target_customer_id = ?"
            params.append(target_customer_id)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

    return {"ok": True, "items": rows}


# -------------------------------------------------------------------
# RUNTIME / KPI / RISK / GATE
# -------------------------------------------------------------------
def get_runtime_controls(symbol: Optional[str] = None) -> Dict[str, Any]:
    return {
        "paused": DEFAULT_PAUSED,
        "allow_new_entries": DEFAULT_ALLOW_NEW_ENTRIES,
        "risk_multiplier": DEFAULT_RISK_MULTIPLIER,
        "symbol": symbol.upper() if symbol else None,
        "source": "default_env",
    }


def get_deals_filtered(
    symbol: Optional[str] = None,
    account: Optional[str] = None,
    magic: Optional[str] = None,
    lookback_days: int = DEFAULT_KPI_LOOKBACK_DAYS,
    limit_trades: int = DEFAULT_KPI_LIMIT_TRADES,
):
    dt_from = now_utc() - timedelta(days=lookback_days)

    query = "SELECT * FROM deals WHERE deal_time_utc >= ?"
    params: List[Any] = [utc_iso(dt_from)]

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

    query = "SELECT * FROM deals WHERE deal_time_utc >= ?"
    params: List[Any] = [utc_iso(dt_from)]

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
            "reasons": ["AUTO_GATE_DISABLED"],
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
            "reasons": reasons_red,
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
            "reasons": reasons_yellow,
        }

    return {
        "gate_level": "GREEN",
        "allow_new_entries": True,
        "risk_multiplier": 1.0,
        "reasons": ["NORMAL"],
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
        limit_trades=limit_trades,
    )
    kpis = summarize_kpis(rows)
    gate = auto_gate_from_kpis(kpis)
    return {"kpis": kpis, "gate": gate}


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
            "reasons": ["RISK_ENGINE_DISABLED"],
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
        "reasons": reasons,
    }


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
            "reasons": ["GATE_RED"],
        }

    if not SCORE_TO_RISK_ENABLED:
        return {
            "mode": mode,
            "score_to_risk_enabled": False,
            "score": score,
            "priority": "NORMAL",
            "risk_multiplier": RISK_MULTIPLIER_NORMAL,
            "approved": True,
            "reasons": ["SCORE_TO_RISK_DISABLED"],
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
        "reasons": reasons,
    }


# -------------------------------------------------------------------
# CONSUMERS / HEARTBEAT / SIGNALS
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
    for r in latest_map.values():
        last_seen = parse_dt(r.get("last_seen_utc"))
        if not last_seen or last_seen < cutoff:
            continue

        account = safe_str(r.get("account"))
        magic = safe_str(r.get("magic"))
        hb_symbol = safe_str(r.get("symbol")).upper()

        if account and magic and hb_symbol == symbol:
            consumers.append({
                "account": account,
                "magic": magic,
                "symbol": hb_symbol,
                "enabled": 1,
                "owner_name": r.get("owner_name"),
                "notes": "heartbeat_fallback",
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
    return {"ok": True, "count": len(items), "items": items}


@app.post("/consumers/upsert")
def consumers_upsert(
    data: ConsumerUpsertIn,
    _: bool = Depends(app_token_guard),
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
            now,
        ))
        conn.commit()
        conn.close()

    return {
        "ok": True,
        "account": account,
        "magic": magic,
        "symbol": symbol,
        "enabled": data.enabled,
    }


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
            data.owner_name,
        ))
        conn.commit()
        conn.close()

    return {"ok": True, "server_time_utc": now}


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

    for r in latest_map.values():
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
        "items": result,
    }


def signal_passes_filter(signal_row: Dict[str, Any], gate_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = signal_row.get("payload", {}) or {}
    score = safe_float(payload.get("score"), 1.0)
    gate_level = ((gate_payload or {}).get("gate_level") or "UNKNOWN").upper()

    if gate_level == "RED":
        return {"approved": False, "reason": "GATE_RED", "score": score}
    if score < 0.60:
        return {"approved": False, "reason": "SCORE_LT_0_60", "score": score}
    if gate_level == "YELLOW" and score < 0.75:
        return {"approved": False, "reason": "YELLOW_SCORE_LT_0_75", "score": score}
    return {"approved": True, "reason": "APPROVED", "score": score}


def create_signal_deliveries(signal_id: int, symbol: str) -> List[Dict[str, Any]]:
    symbol = symbol.upper()
    targets = resolve_target_consumers(symbol)
    now = utc_iso()
    created = []

    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        for t in targets:
            account = safe_str(t.get("account"))
            magic = safe_str(t.get("magic"))
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
                now,
            ))

            created.append({
                "signal_id": signal_id,
                "account": account,
                "magic": magic,
                "symbol": symbol,
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
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
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

    deliveries = create_signal_deliveries(signal_id=signal_id, symbol=symbol)

    return {
        "ok": True,
        "signal_id": signal_id,
        "symbol": symbol,
        "side": side,
        "created_utc": now,
        "deliveries_created": len(deliveries),
        "deliveries": deliveries,
    }


def get_latest_delivery_for_consumer(symbol: str, account: str, magic: Optional[str]) -> Optional[Dict[str, Any]]:
    magic = magic or ""
    with DB_LOCK:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        SELECT d.*, s.side, s.payload_json, s.updated_utc AS signal_updated_utc,
               s.created_utc AS signal_created_utc, s.status AS signal_status
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
            "gate": gate_payload,
        }

    delivery = get_latest_delivery_for_consumer(symbol=symbol, account=account, magic=magic)

    if not delivery:
        return {
            "ok": True,
            "has_signal": False,
            "symbol": symbol,
            "blocked": False,
            "controls": controls,
            "gate": gate_payload,
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
    execution_engine = compute_execution_engine(signal_row, gate_payload)

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
            },
        }

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
            },
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
        "delivery": {
            "delivery_id": delivery["id"],
            "signal_id": delivery["signal_id"],
            "delivery_status": delivery["delivery_status"],
            "first_seen_utc": delivery.get("first_seen_utc"),
            "ack_utc": delivery.get("ack_utc"),
        },
        "signal": signal_row,
    }


@app.post("/ack")
def ack_signal(data: AckIn):
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
        INSERT OR IGNORE INTO signal_acks(signal_id, symbol, account, magic, ack_utc)
        VALUES (?, ?, ?, ?, ?)
        """, (signal_id, symbol, account, magic, ack_time))

        conn.commit()
        conn.close()

    return {
        "ok": True,
        "signal_id": signal_id,
        "delivery_id": delivery_id,
        "symbol": symbol,
        "account": account,
        "magic": magic,
    }


# -------------------------------------------------------------------
# DEAL / RISK
# -------------------------------------------------------------------
def resolve_signal_id_for_deal(
    account: Optional[str],
    magic: Optional[str],
    symbol: str,
    explicit_signal_id: Optional[int],
) -> Optional[int]:
    if explicit_signal_id:
        return explicit_signal_id

    account = safe_str(account)
    magic = safe_str(magic)
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

    return row["signal_id"] if row else None


@app.post("/deal")
def post_deal(data: DealIn):
    deal_time = data.deal_time_utc or utc_iso()
    symbol = data.symbol.upper()
    resolved_signal_id = resolve_signal_id_for_deal(
        account=data.account,
        magic=data.magic,
        symbol=symbol,
        explicit_signal_id=data.signal_id,
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
            resolved_signal_id,
        ))
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
            utc_iso(),
        ))
        conn.commit()
        conn.close()

    return {"ok": True}


# -------------------------------------------------------------------
# STATUS / KPI / DEBUG
# -------------------------------------------------------------------
@app.get("/controls/effective")
def controls_effective(
    symbol: Optional[str] = Query(default=None),
    _: bool = Depends(app_token_guard),
):
    return {"ok": True, "controls": get_runtime_controls(symbol)}


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
        limit_trades=limit_trades,
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
        "gate": result["gate"],
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
        "risk_engine": result,
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
            "gate_level": gate_level.upper(),
        },
        "execution_engine": result,
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
        "reasons": reasons,
    }


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
        limit_trades=limit_trades,
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
        "kpis": kpis,
    }


@app.get("/status/system_overview")
def system_overview(
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
        limit_trades=limit_trades,
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
        "risk_engine": risk_engine,
    }


@app.get("/debug/state")
def debug_state(symbol: str = Query(...)):
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
        "deliveries": deliveries,
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
        params: List[Any] = []

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
        "items": rows,
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
        "deliveries": deliveries,
    }


@app.get("/debug/pending_by_consumer")
def debug_pending_by_consumer(
    account: str = Query(...),
    magic: str = Query(...),
    symbol: str = Query(...),
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
        "items": rows,
    }
