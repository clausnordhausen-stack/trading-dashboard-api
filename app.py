from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import os

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Signal Agent API", version="6.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

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

# customer setup per email/account/strategy
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


# =========================================================
# HELPERS
# =========================================================

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_token(email: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
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


def infer_gate_level(symbol: str) -> str:
    symbol = symbol.upper()
    if symbol in ("XAUUSD", "BTCUSD"):
        return "GREEN"
    return "YELLOW"


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


# =========================================================
# BASIC
# =========================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "version": "6.2.0",
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
# CUSTOMER ACCOUNTS / SETUP
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
# FLUTTER MONITORING ENDPOINTS
# =========================================================

@app.get("/status/system_overview")
def system_overview(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()

    current_setup = None
    for account_item in get_customer_accounts_with_setup(current_user["email"]):
        if account_item["account_number"] == account:
            for strategy in account_item["symbols"]:
                if strategy["symbol"] == symbol_upper:
                    current_setup = strategy
                    break

    enabled = current_setup["enabled"] if current_setup else True
    risk_tier = current_setup["risk_tier"] if current_setup else "balanced"

    return {
        "ok": True,
        "server_time_utc": now_utc_iso(),
        "filters": {
            "symbol": symbol_upper,
            "account": account,
            "magic": magic,
        },
        "heartbeat": {
            "ok": True,
            "connected_count": 1,
            "items": [
                {
                    "symbol": symbol_upper,
                    "account": account,
                    "magic": magic,
                    "connected": True,
                    "last_seen_utc": now_utc_iso(),
                    "ea_name": f"{symbol_upper} Core EA",
                    "version": "1.0.0",
                    "status": "alive",
                }
            ],
        },
        "controls": {
            "paused": False,
            "allow_new_entries": enabled,
            "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            "symbol": symbol_upper,
            "source": "customer_setup",
        },
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
        "gate": {
            "ok": True,
            "symbol": symbol_upper,
            "gate_level": "GREEN" if enabled else "RED",
            "allow_new_entries": enabled,
            "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            "paused": False,
            "controls": {
                "paused": False,
                "allow_new_entries": enabled,
                "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            },
            "auto_gate": {
                "gate_level": "GREEN" if enabled else "RED",
                "allow_new_entries": enabled,
                "risk_multiplier": risk_multiplier_for_tier(risk_tier),
                "reasons": ["CUSTOMER_SETUP_ACTIVE" if enabled else "STRATEGY_DISABLED"],
            },
            "risk_engine": {
                "enabled": True,
                "allow_new_entries": enabled,
                "risk_level": "GREEN" if enabled else "RED",
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
            "reasons": ["NORMAL" if enabled else "STRATEGY_DISABLED"],
        },
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": enabled,
            "risk_level": "GREEN" if enabled else "RED",
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
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()

    current_setup = None
    for account_item in get_customer_accounts_with_setup(current_user["email"]):
        if account_item["account_number"] == account:
            for strategy in account_item["symbols"]:
                if strategy["symbol"] == symbol_upper:
                    current_setup = strategy
                    break

    enabled = current_setup["enabled"] if current_setup else True

    return {
        "ok": True,
        "filters": {
            "symbol": symbol_upper,
            "account": account,
            "magic": magic,
        },
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": enabled,
            "risk_level": "GREEN" if enabled else "RED",
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


@app.get("/status/gate_combo")
def gate_combo(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()

    current_setup = None
    for account_item in get_customer_accounts_with_setup(current_user["email"]):
        if account_item["account_number"] == account:
            for strategy in account_item["symbols"]:
                if strategy["symbol"] == symbol_upper:
                    current_setup = strategy
                    break

    enabled = current_setup["enabled"] if current_setup else True
    risk_tier = current_setup["risk_tier"] if current_setup else "balanced"

    return {
        "ok": True,
        "symbol": symbol_upper,
        "gate_level": "GREEN" if enabled else "RED",
        "allow_new_entries": enabled,
        "risk_multiplier": risk_multiplier_for_tier(risk_tier),
        "paused": False,
        "controls": {
            "paused": False,
            "allow_new_entries": enabled,
            "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            "symbol": symbol_upper,
            "source": "customer_setup",
        },
        "auto_gate": {
            "gate_level": "GREEN" if enabled else "RED",
            "allow_new_entries": enabled,
            "risk_multiplier": risk_multiplier_for_tier(risk_tier),
            "reasons": ["CUSTOMER_SETUP_ACTIVE" if enabled else "STRATEGY_DISABLED"],
        },
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": enabled,
            "risk_level": "GREEN" if enabled else "RED",
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
        "reasons": ["NORMAL" if enabled else "STRATEGY_DISABLED"],
    }


@app.get("/status/heartbeat")
def heartbeat_status(
    symbol: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "ok": True,
        "timeout_sec": 90,
        "connected_count": 1,
        "items": [
            {
                "account": "connected",
                "magic": "n/a",
                "symbol": symbol.upper(),
                "ea_name": f"{symbol.upper()} Core EA",
                "version": "1.0.0",
                "last_seen_utc": now_utc_iso(),
                "connected": True,
                "status": "alive",
                "comment": "mock heartbeat",
                "owner_name": current_user["email"],
            }
        ],
    }


@app.get("/latest")
def latest_signal(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    symbol_upper = symbol.upper()

    current_setup = None
    for account_item in get_customer_accounts_with_setup(current_user["email"]):
        if account_item["account_number"] == account:
            for strategy in account_item["symbols"]:
                if strategy["symbol"] == symbol_upper:
                    current_setup = strategy
                    break

    enabled = current_setup["enabled"] if current_setup else True

    return {
        "ok": True,
        "has_signal": False,
        "blocked": not enabled,
        "reason": None if enabled else "STRATEGY_DISABLED",
        "symbol": symbol_upper,
        "controls": {
            "paused": False,
            "allow_new_entries": enabled,
            "risk_multiplier": 1.0,
        },
        "gate": {
            "gate_level": "GREEN" if enabled else "RED",
            "allow_new_entries": enabled,
            "risk_multiplier": 1.0,
        },
        "filter": {
            "approved": enabled,
            "reason": "NO_SIGNAL" if enabled else "STRATEGY_DISABLED",
            "score": None,
        },
        "signal": None,
    }


@app.get("/debug/state")
def debug_state(
    symbol: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "ok": True,
        "symbol": symbol.upper(),
        "signals": [],
        "deliveries": [],
    }


@app.get("/debug/recent_acks")
def debug_recent_acks(
    symbol: Optional[str] = Query(default=None),
    account: Optional[str] = Query(default=None),
    magic: Optional[str] = Query(default=None),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "ok": True,
        "count": 0,
        "items": [],
        "acks": [],
        "filters": {
            "symbol": symbol.upper() if symbol else None,
            "account": account,
            "magic": magic,
        },
    }


@app.get("/debug/delivery_status")
def debug_delivery_status(
    signal_id: int = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "ok": True,
        "signal": {
            "id": signal_id,
            "status": "not_implemented",
        },
        "delivery_count": 0,
        "deliveries": [],
    }


@app.get("/debug/pending_by_consumer")
def debug_pending_by_consumer(
    account: str = Query(...),
    magic: str = Query(...),
    symbol: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "ok": True,
        "count": 0,
        "items": [],
        "filters": {
            "account": account,
            "magic": magic,
            "symbol": symbol.upper(),
        },
    }
