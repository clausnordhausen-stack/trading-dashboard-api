from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import json
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Signal Agent API", version="6.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# CONFIG
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

TV_API_KEY = os.getenv("TV_API_KEY", "supersecret123")
HEARTBEAT_TIMEOUT_SEC = int(os.getenv("HEARTBEAT_TIMEOUT_SEC", "90"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =========================================================
# IN-MEMORY DEMO DATA
# =========================================================

FAKE_USERS: Dict[str, Dict[str, str]] = {
    "test@test.com": {
        "password": "123456",
        "role": "customer",
    },
    "admin@claus.digital": {
        "password": "123456",
        "role": "master",
    },
}

FAKE_CUSTOMER_ACCOUNTS: Dict[str, List[Dict[str, Any]]] = {
    "test@test.com": [
        {
            "id": 1,
            "account_number": "10001",
            "broker": "IC Markets",
        },
        {
            "id": 2,
            "account_number": "10002",
            "broker": "FTMO",
        },
    ],
    "admin@claus.digital": [
        {
            "id": 10,
            "account_number": "90001",
            "broker": "Master View",
        },
    ],
}

FAKE_ACCOUNT_STRATEGIES: Dict[int, List[Dict[str, Any]]] = {
    1: [
        {
            "symbol": "XAUUSD",
            "name": "Gold Core",
            "magic": "61001",
        },
        {
            "symbol": "BTCUSD",
            "name": "BTC Core",
            "magic": "61002",
        },
    ],
    2: [
        {
            "symbol": "XAUUSD",
            "name": "Gold Core",
            "magic": "61001",
        },
        {
            "symbol": "BTCUSD",
            "name": "BTC Core",
            "magic": "61002",
        },
    ],
    10: [
        {
            "symbol": "XAUUSD",
            "name": "Gold Master",
            "magic": "777",
        },
        {
            "symbol": "BTCUSD",
            "name": "BTC Master",
            "magic": "62001",
        },
    ],
}

FAKE_CUSTOMER_SETUP: Dict[str, Dict[int, Dict[str, Dict[str, Any]]]] = {
    "test@test.com": {
        1: {
            "XAUUSD": {
                "enabled": True,
                "risk_tier": "balanced",
            },
            "BTCUSD": {
                "enabled": True,
                "risk_tier": "balanced",
            },
        },
        2: {
            "XAUUSD": {
                "enabled": True,
                "risk_tier": "balanced",
            },
            "BTCUSD": {
                "enabled": True,
                "risk_tier": "balanced",
            },
        },
    },
    "admin@claus.digital": {
        10: {
            "XAUUSD": {
                "enabled": True,
                "risk_tier": "balanced",
            },
            "BTCUSD": {
                "enabled": True,
                "risk_tier": "balanced",
            },
        },
    },
}

# runtime memory for signals / heartbeats / acks
SIGNALS: List[Dict[str, Any]] = []
SIGNAL_ACKS: List[Dict[str, Any]] = []
HEARTBEATS: List[Dict[str, Any]] = []

# =========================================================
# MODELS
# =========================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str


class StrategySetupIn(BaseModel):
    enabled: bool
    risk_tier: str


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


# =========================================================
# HELPERS
# =========================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_utc_iso() -> str:
    return now_utc().isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def create_token(email: str, role: str) -> str:
    expire = now_utc() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        role = payload.get("role", "customer")

        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        return {
            "email": email,
            "role": role,
        }
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def get_user_accounts(email: str) -> List[Dict[str, Any]]:
    return FAKE_CUSTOMER_ACCOUNTS.get(email, [])


def get_account_strategies(account_id: int) -> List[Dict[str, Any]]:
    return FAKE_ACCOUNT_STRATEGIES.get(account_id, [])


def ensure_account_access(email: str, account_id: int) -> None:
    accounts = get_user_accounts(email)
    allowed_ids = {int(item["id"]) for item in accounts}
    if account_id not in allowed_ids:
        raise HTTPException(status_code=404, detail="Account not found")


def get_strategy_setup(email: str, account_id: int, symbol: str) -> Dict[str, Any]:
    symbol = symbol.upper()
    account_setup = FAKE_CUSTOMER_SETUP.setdefault(email, {}).setdefault(account_id, {})
    return account_setup.setdefault(
        symbol,
        {
            "enabled": True,
            "risk_tier": "balanced",
        },
    )


def get_customer_accounts_with_setup(email: str) -> List[Dict[str, Any]]:
    accounts = get_user_accounts(email)
    result: List[Dict[str, Any]] = []

    for account in accounts:
        account_id = int(account["id"])
        base_strategies = get_account_strategies(account_id)
        enriched_strategies: List[Dict[str, Any]] = []

        for strategy in base_strategies:
            symbol = strategy["symbol"].upper()
            setup = get_strategy_setup(email, account_id, symbol)

            enriched_strategies.append(
                {
                    "symbol": symbol,
                    "displayName": strategy["name"],
                    "name": strategy["name"],
                    "magic": str(strategy["magic"]),
                    "enabled": bool(setup["enabled"]),
                    "riskTier": setup["risk_tier"],
                    "risk_tier": setup["risk_tier"],
                    "strategyCode": "btc_core" if symbol == "BTCUSD" else "xau_core",
                    "strategy_code": "btc_core" if symbol == "BTCUSD" else "xau_core",
                    "sortOrder": 2 if symbol == "BTCUSD" else 1,
                    "sort_order": 2 if symbol == "BTCUSD" else 1,
                    "baseLot": 0.01,
                    "base_lot": 0.01,
                    "maxLot": 1.00,
                    "max_lot": 1.00,
                    "color": "#F7931A" if symbol == "BTCUSD" else "#D4AF37",
                }
            )

        result.append(
            {
                "id": account_id,
                "account_number": account["account_number"],
                "label": f'{account["broker"]} • {account["account_number"]}',
                "broker": account["broker"],
                "enabled": True,
                "symbols": enriched_strategies,
            }
        )

    return result


def risk_multiplier_for_tier(risk_tier: str) -> float:
    rt = risk_tier.strip().lower()
    if rt == "conservative":
        return 0.5
    if rt == "balanced":
        return 1.0
    if rt == "dynamic":
        return 1.25
    if rt == "aggressive":
        return 1.5
    return 1.0


def normalize_side(value: Optional[str]) -> str:
    text = (value or "").strip().upper()
    if text == "LONG":
        return "BUY"
    if text == "SHORT":
        return "SELL"
    return text


def latest_signal_for(symbol: str) -> Optional[Dict[str, Any]]:
    symbol = symbol.upper()
    matching = [s for s in SIGNALS if s["symbol"] == symbol]
    if not matching:
        return None
    matching.sort(key=lambda x: x["created_utc"], reverse=True)
    return matching[0]


def is_signal_acked(signal_id: int, account: str, magic: str) -> bool:
    for ack in SIGNAL_ACKS:
        if (
            ack["signal_id"] == signal_id
            and ack["account"] == account
            and ack["magic"] == magic
        ):
            return True
    return False


def cleanup_heartbeats() -> List[Dict[str, Any]]:
    cutoff = now_utc() - timedelta(seconds=HEARTBEAT_TIMEOUT_SEC)
    active: List[Dict[str, Any]] = []

    for hb in HEARTBEATS:
        last_seen = parse_dt(hb.get("last_seen_utc"))
        if last_seen and last_seen >= cutoff:
            active.append(hb)

    return active


def find_strategy_for_account_symbol_magic(
    account_number: str,
    symbol: str,
    magic: str,
) -> Optional[Dict[str, Any]]:
    symbol_upper = symbol.upper()
    magic_norm = str(magic).strip()

    for email in FAKE_CUSTOMER_ACCOUNTS.keys():
        for account in get_customer_accounts_with_setup(email):
            if account["account_number"] != account_number:
                continue

            for strategy in account["symbols"]:
                if (
                    strategy["symbol"].upper() == symbol_upper
                    and str(strategy["magic"]).strip() == magic_norm
                ):
                    return strategy

    return None


def build_controls(enabled: bool, symbol: str, risk_tier: str) -> Dict[str, Any]:
    return {
        "paused": False,
        "allow_new_entries": enabled,
        "risk_multiplier": risk_multiplier_for_tier(risk_tier) if enabled else 0.0,
        "symbol": symbol.upper(),
        "source": "customer_setup",
    }


def build_risk_engine(enabled: bool) -> Dict[str, Any]:
    level = "GREEN" if enabled else "RED"
    return {
        "enabled": True,
        "allow_new_entries": enabled,
        "risk_level": level,
        "daily_pnl": 0.0,
        "daily_r": 0.0,
        "daily_trades": 0,
        "limits": {
            "daily_loss_cap_usd": 250.0,
            "daily_r_cap": -5.0,
            "daily_max_trades": 10,
        },
        "reasons": ["NORMAL" if enabled else "STRATEGY_DISABLED"],
    }


def build_gate_combo_payload(symbol: str, enabled: bool, risk_tier: str) -> Dict[str, Any]:
    level = "GREEN" if enabled else "RED"
    multiplier = risk_multiplier_for_tier(risk_tier) if enabled else 0.0
    risk_engine = build_risk_engine(enabled)

    return {
        "ok": True,
        "symbol": symbol.upper(),
        "gate_level": level,
        "allow_new_entries": enabled,
        "risk_multiplier": multiplier,
        "paused": False,
        "controls": build_controls(enabled, symbol, risk_tier),
        "auto_gate": {
            "gate_level": level,
            "allow_new_entries": enabled,
            "risk_multiplier": multiplier,
            "reasons": ["CUSTOMER_SETUP_ACTIVE" if enabled else "STRATEGY_DISABLED"],
        },
        "risk_engine": risk_engine,
        "reasons": ["NORMAL" if enabled else "STRATEGY_DISABLED"],
    }


def build_mock_heartbeat_item(symbol: str) -> Dict[str, Any]:
    return {
        "account": "connected",
        "magic": "n/a",
        "symbol": symbol.upper(),
        "ea_name": f"{symbol.upper()} Core EA",
        "version": "1.0.0",
        "last_seen_utc": now_utc_iso(),
        "connected": True,
        "status": "alive",
        "comment": "mock heartbeat",
        "owner_name": "system",
    }


# =========================================================
# BASIC
# =========================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "version": "6.4.0",
        "server_time_utc": now_utc_iso(),
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "time_utc": now_utc_iso(),
    }


# =========================================================
# AUTH
# =========================================================

@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest) -> Dict[str, str]:
    email = data.email.strip().lower()
    password = data.password.strip()

    user = FAKE_USERS.get(email)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(email=email, role=user["role"])

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/me")
def me(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    email = current_user["email"]
    role = current_user["role"]

    return {
        "email": email,
        "role": role,
        "display_name": email,
        "access_status": "active",
        "trading_status": "enabled",
        "subscription_status": "active",
    }


# =========================================================
# CUSTOMER ACCOUNTS / SETUP (AUTH REQUIRED)
# =========================================================

@app.get("/accounts")
def get_accounts(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    return get_user_accounts(current_user["email"])


@app.get("/accounts/{account_id}/strategies")
def get_strategies(
    account_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    ensure_account_access(current_user["email"], account_id)
    return get_account_strategies(account_id)


@app.get("/customer/setup")
def customer_setup(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    items = get_customer_accounts_with_setup(current_user["email"])
    return {
        "ok": True,
        "items": items,
    }


@app.post("/accounts/{account_id}/strategies/{symbol}/setup")
def update_strategy_setup(
    account_id: int,
    symbol: str,
    data: StrategySetupIn,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    email = current_user["email"]
    ensure_account_access(email, account_id)

    symbol_upper = symbol.strip().upper()
    strategies = get_account_strategies(account_id)
    valid_symbols = {item["symbol"].upper() for item in strategies}
    if symbol_upper not in valid_symbols:
        raise HTTPException(status_code=404, detail="Strategy not found")

    normalized_risk = data.risk_tier.strip().lower()
    if normalized_risk not in ("conservative", "balanced", "dynamic", "aggressive"):
        raise HTTPException(status_code=422, detail="Invalid risk_tier")

    setup = get_strategy_setup(email, account_id, symbol_upper)
    setup["enabled"] = bool(data.enabled)
    setup["risk_tier"] = normalized_risk

    return {
        "ok": True,
        "account_id": account_id,
        "symbol": symbol_upper,
        "enabled": setup["enabled"],
        "risk_tier": setup["risk_tier"],
    }


# =========================================================
# TV WEBHOOK / SIGNAL FLOW (PUBLIC)
# =========================================================

@app.post("/tv")
def tv_signal(
    data: TVSignalIn,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
) -> Dict[str, Any]:
    provided_key = x_api_key or data.key
    if provided_key != TV_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    symbol = data.symbol.strip().upper()
    side = normalize_side(data.side or data.action)

    if side not in ("BUY", "SELL"):
        raise HTTPException(status_code=422, detail="side/action must be BUY or SELL")

    payload = dict(data.payload or {})
    payload["score"] = data.score if data.score is not None else 1.0

    signal_id = len(SIGNALS) + 1
    now_iso = now_utc_iso()

    row = {
        "id": signal_id,
        "symbol": symbol,
        "side": side,
        "payload": payload,
        "payload_json": json.dumps(payload, ensure_ascii=False),
        "created_utc": now_iso,
        "updated_utc": now_iso,
        "status": "pending",
    }
    SIGNALS.append(row)

    return {
        "ok": True,
        "signal_id": signal_id,
        "symbol": symbol,
        "side": side,
        "created_utc": row["created_utc"],
    }


@app.get("/latest")
def latest_signal(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()

    strategy = find_strategy_for_account_symbol_magic(
        account_number=account,
        symbol=symbol_upper,
        magic=magic,
    )

    if strategy is None:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": True,
            "reason": "STRATEGY_NOT_ASSIGNED",
            "symbol": symbol_upper,
            "controls": {
                "paused": False,
                "allow_new_entries": False,
                "risk_multiplier": 0.0,
            },
            "gate": {
                "gate_level": "RED",
                "allow_new_entries": False,
                "risk_multiplier": 0.0,
            },
            "filter": {
                "approved": False,
                "reason": "STRATEGY_NOT_ASSIGNED",
                "score": None,
            },
            "signal": None,
        }

    enabled = bool(strategy["enabled"])
    risk_tier = strategy.get("risk_tier", "balanced")

    if not enabled:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": True,
            "reason": "STRATEGY_DISABLED",
            "symbol": symbol_upper,
            "controls": {
                "paused": False,
                "allow_new_entries": False,
                "risk_multiplier": 0.0,
            },
            "gate": {
                "gate_level": "RED",
                "allow_new_entries": False,
                "risk_multiplier": 0.0,
            },
            "filter": {
                "approved": False,
                "reason": "STRATEGY_DISABLED",
                "score": None,
            },
            "signal": None,
        }

    signal = latest_signal_for(symbol_upper)
    if signal is None:
        return {
            "ok": True,
            "has_signal": False,
            "blocked": False,
            "reason": None,
            "symbol": symbol_upper,
            "controls": build_controls(True, symbol_upper, risk_tier),
            "gate": {
                "gate_level": "GREEN",
                "allow_new_entries": True,
                "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            },
            "filter": {
                "approved": True,
                "reason": "NO_SIGNAL",
                "score": None,
            },
            "signal": None,
        }

    if is_signal_acked(signal["id"], account, magic):
        return {
            "ok": True,
            "has_signal": False,
            "blocked": False,
            "reason": "ALREADY_ACKED",
            "symbol": symbol_upper,
            "controls": build_controls(True, symbol_upper, risk_tier),
            "gate": {
                "gate_level": "GREEN",
                "allow_new_entries": True,
                "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            },
            "filter": {
                "approved": True,
                "reason": "ALREADY_ACKED",
                "score": signal["payload"].get("score"),
            },
            "signal": None,
        }

    return {
        "ok": True,
        "has_signal": True,
        "blocked": False,
        "reason": None,
        "symbol": symbol_upper,
        "controls": build_controls(True, symbol_upper, risk_tier),
        "gate": {
            "gate_level": "GREEN",
            "allow_new_entries": True,
            "risk_multiplier": risk_multiplier_for_tier(risk_tier),
        },
        "filter": {
            "approved": True,
            "reason": "APPROVED",
            "score": signal["payload"].get("score"),
        },
        "execution_engine": {
            "mode": "customer_setup",
            "score_to_risk_enabled": True,
            "score": signal["payload"].get("score"),
            "priority": "NORMAL",
            "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            "approved": True,
            "reasons": ["CUSTOMER_SETUP_ACTIVE"],
        },
        "effective_risk_multiplier": risk_multiplier_for_tier(risk_tier),
        "delivery": {
            "delivery_id": signal["id"],
            "signal_id": signal["id"],
            "delivery_status": "pending",
            "first_seen_utc": signal["created_utc"],
            "ack_utc": None,
        },
        "signal": signal,
    }


@app.post("/ack")
def ack_signal(data: AckIn) -> Dict[str, Any]:
    symbol_upper = data.symbol.strip().upper()
    magic = (data.magic or "").strip()

    signal = None
    for item in SIGNALS:
        if (
            item["symbol"] == symbol_upper
            and item["updated_utc"] == data.updated_utc
        ):
            signal = item
            break

    if signal is None:
        raise HTTPException(status_code=404, detail="Signal not found")

    if not is_signal_acked(signal["id"], data.account, magic):
        SIGNAL_ACKS.append(
            {
                "signal_id": signal["id"],
                "symbol": symbol_upper,
                "account": data.account,
                "magic": magic,
                "ack_utc": now_utc_iso(),
                "ticket": data.ticket,
            }
        )

    return {
        "ok": True,
        "signal_id": signal["id"],
        "symbol": symbol_upper,
        "account": data.account,
        "magic": magic,
    }


# =========================================================
# HEARTBEAT (PUBLIC)
# =========================================================

@app.post("/hb")
def heartbeat(data: HeartbeatPing) -> Dict[str, Any]:
    if data.key and data.key != TV_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid key")

    row = {
        "account": data.account,
        "magic": data.magic,
        "symbol": data.symbol.upper(),
        "ea_name": data.ea_name,
        "version": data.version,
        "last_seen_utc": now_utc_iso(),
        "connected": True,
        "status": data.status,
        "comment": data.comment,
        "owner_name": data.owner_name,
    }

    HEARTBEATS.append(row)

    return {
        "ok": True,
        "server_time_utc": now_utc_iso(),
    }


@app.get("/status/heartbeat")
def heartbeat_status(
    symbol: str = Query(...),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()
    active = cleanup_heartbeats()
    items = [hb for hb in active if hb["symbol"] == symbol_upper]

    if not items:
        items = [build_mock_heartbeat_item(symbol_upper)]

    return {
        "ok": True,
        "timeout_sec": HEARTBEAT_TIMEOUT_SEC,
        "connected_count": len(items),
        "items": items,
    }


# =========================================================
# STATUS / DASHBOARD (PUBLIC)
# =========================================================

@app.get("/status/system_overview")
def system_overview(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()

    strategy = find_strategy_for_account_symbol_magic(
        account_number=account,
        symbol=symbol_upper,
        magic=magic,
    )

    enabled = bool(strategy["enabled"]) if strategy else False
    risk_tier = strategy.get("risk_tier", "balanced") if strategy else "balanced"
    gate_level = "GREEN" if enabled else "RED"
    gate_combo_payload = build_gate_combo_payload(symbol_upper, enabled, risk_tier)

    return {
        "ok": True,
        "server_time_utc": now_utc_iso(),
        "filters": {
            "symbol": symbol_upper,
            "account": account,
            "magic": magic,
        },
        "heartbeat": heartbeat_status(symbol=symbol_upper),
        "controls": build_controls(enabled, symbol_upper, risk_tier),
        "kpis": {
            "total_trades": 0,
            "wins": 0,
            "losses": 0,
            "breakeven": 0,
            "winrate_pct": 0.0,
            "gross_profit": 0.0,
            "gross_loss": 0.0,
            "net_pnl": 0.0,
            "avg_pnl": 0.0,
            "sum_r": 0.0,
            "avg_r": 0.0,
            "profit_factor": 0.0,
            "max_drawdown_abs": 0.0,
            "max_drawdown_pct": 0.0,
            "max_loss_streak": 0,
            "current_loss_streak": 0,
            "last_trade_time_utc": None,
        },
        "gate": gate_combo_payload,
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": enabled,
            "risk_level": gate_level,
            "daily_pnl": 0.0,
            "daily_r": 0.0,
            "daily_trades": 0,
            "limits": {
                "daily_loss_cap_usd": 250.0,
                "daily_r_cap": -5.0,
                "daily_max_trades": 10,
            },
            "reasons": ["NORMAL" if enabled else "STRATEGY_DISABLED"],
        },
    }


@app.get("/status/risk_engine")
def status_risk_engine(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
) -> Dict[str, Any]:
    strategy = find_strategy_for_account_symbol_magic(
        account_number=account,
        symbol=symbol.upper(),
        magic=magic,
    )

    enabled = bool(strategy["enabled"]) if strategy else False

    return {
        "ok": True,
        "filters": {
            "symbol": symbol.upper(),
            "account": account,
            "magic": magic,
        },
        "risk_engine": build_risk_engine(enabled),
    }


@app.get("/status/gate_combo")
def gate_combo(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
) -> Dict[str, Any]:
    strategy = find_strategy_for_account_symbol_magic(
        account_number=account,
        symbol=symbol.upper(),
        magic=magic,
    )

    enabled = bool(strategy["enabled"]) if strategy else False
    risk_tier = strategy.get("risk_tier", "balanced") if strategy else "balanced"

    return build_gate_combo_payload(symbol, enabled, risk_tier)


# =========================================================
# DEBUG (PUBLIC)
# =========================================================

@app.get("/debug/state")
def debug_state(
    symbol: str = Query(...),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()
    signals = [s for s in SIGNALS if s["symbol"] == symbol_upper]

    return {
        "ok": True,
        "symbol": symbol_upper,
        "signals": signals[-10:],
        "deliveries": signals[-50:],
    }


@app.get("/debug/recent_acks")
def debug_recent_acks(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    rows = SIGNAL_ACKS

    if symbol:
        rows = [r for r in rows if r["symbol"] == symbol.upper()]
    if account:
        rows = [r for r in rows if r["account"] == account]
    if magic:
        rows = [r for r in rows if r["magic"] == magic]

    rows = sorted(rows, key=lambda x: x["ack_utc"], reverse=True)

    return {
        "ok": True,
        "count": len(rows),
        "items": rows[:100],
        "acks": rows[:100],
        "filters": {
            "symbol": symbol.upper() if symbol else None,
            "account": account,
            "magic": magic,
        },
    }


@app.get("/debug/delivery_status")
def debug_delivery_status(
    signal_id: int = Query(...),
) -> Dict[str, Any]:
    signal = next((s for s in SIGNALS if s["id"] == signal_id), None)

    return {
        "ok": True,
        "signal": signal,
        "delivery_count": 0,
        "deliveries": [],
    }


@app.get("/debug/pending_by_consumer")
def debug_pending_by_consumer(
    account: str = Query(...),
    magic: str = Query(...),
    symbol: str = Query(...),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()
    latest = latest_signal_for(symbol_upper)

    items: List[Dict[str, Any]] = []
    if latest and not is_signal_acked(latest["id"], account, magic):
        items.append(
            {
                "signal_id": latest["id"],
                "symbol": symbol_upper,
                "account": account,
                "magic": magic,
                "delivery_status": "pending",
                "payload": latest.get("payload", {}),
                "signal_created_utc": latest.get("created_utc"),
                "signal_updated_utc": latest.get("updated_utc"),
            }
        )

    return {
        "ok": True,
        "count": len(items),
        "items": items,
        "filters": {
            "account": account,
            "magic": magic,
            "symbol": symbol_upper,
        },
    }
