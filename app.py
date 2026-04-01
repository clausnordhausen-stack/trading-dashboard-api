from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import json
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Signal Agent API", version="6.7.0")

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

FAKE_USERS: Dict[str, Dict[str, Any]] = {
    "test@test.com": {
        "password": "123456",
        "role": "customer",
        "customer_id": 1,
        "display_name": "Test Customer",
        "access_status": "active",
        "trading_status": "enabled",
        "subscription_status": "active",
    },
    "admin@claus.digital": {
        "password": "123456",
        "role": "master",
        "customer_id": None,
        "display_name": "Master Admin",
        "access_status": "active",
        "trading_status": "enabled",
        "subscription_status": "active",
    },
}

FAKE_CUSTOMERS: Dict[int, Dict[str, Any]] = {
    1: {
        "id": 1,
        "display_name": "Test Customer",
        "access_start_at": None,
        "access_end_at": None,
        "access_status": "active",
        "trading_status": "enabled",
        "subscription_status": "active",
        "grace_until": None,
    },
}

FAKE_CUSTOMER_ACCOUNTS: Dict[str, List[Dict[str, Any]]] = {
    "test@test.com": [
        {
            "id": 1,
            "account_number": "10001",
            "broker": "IC Markets",
            "broker_name": "IC Markets",
            "account_label": "IC Markets • 10001",
            "is_active": True,
        },
        {
            "id": 2,
            "account_number": "10002",
            "broker": "FTMO",
            "broker_name": "FTMO",
            "account_label": "FTMO • 10002",
            "is_active": True,
        },
    ],
    "admin@claus.digital": [
        {
            "id": 10,
            "account_number": "90001",
            "broker": "Master View",
            "broker_name": "Master View",
            "account_label": "Master View • 90001",
            "is_active": True,
        },
    ],
}

FAKE_ACCOUNT_STRATEGIES: Dict[int, List[Dict[str, Any]]] = {
    1: [
        {
            "id": 1,
            "account_id": 1,
            "symbol": "XAUUSD",
            "name": "Gold Core",
            "strategy_name": "Gold Core",
            "strategy_code": "xau_core",
            "magic": "61001",
            "risk_tier": "balanced",
            "is_enabled": True,
        },
        {
            "id": 2,
            "account_id": 1,
            "symbol": "BTCUSD",
            "name": "BTC Core",
            "strategy_name": "BTC Core",
            "strategy_code": "btc_core",
            "magic": "61002",
            "risk_tier": "balanced",
            "is_enabled": True,
        },
    ],
    2: [
        {
            "id": 3,
            "account_id": 2,
            "symbol": "XAUUSD",
            "name": "Gold Core",
            "strategy_name": "Gold Core",
            "strategy_code": "xau_core",
            "magic": "61001",
            "risk_tier": "balanced",
            "is_enabled": True,
        },
        {
            "id": 4,
            "account_id": 2,
            "symbol": "BTCUSD",
            "name": "BTC Core",
            "strategy_name": "BTC Core",
            "strategy_code": "btc_core",
            "magic": "61002",
            "risk_tier": "balanced",
            "is_enabled": True,
        },
    ],
    10: [
        {
            "id": 5,
            "account_id": 10,
            "symbol": "XAUUSD",
            "name": "Gold Master",
            "strategy_name": "Gold Master",
            "strategy_code": "xau_core",
            "magic": "777",
            "risk_tier": "balanced",
            "is_enabled": True,
        },
        {
            "id": 6,
            "account_id": 10,
            "symbol": "BTCUSD",
            "name": "BTC Master",
            "strategy_name": "BTC Master",
            "strategy_code": "btc_core",
            "magic": "62001",
            "risk_tier": "balanced",
            "is_enabled": True,
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

AUDIT_LOGS: List[Dict[str, Any]] = []

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


class CustomerAccountCreate(BaseModel):
    broker_name: str
    account_number: str
    account_label: str
    is_active: bool = True


class CustomerAccountUpdate(BaseModel):
    broker_name: str
    account_number: str
    account_label: str
    is_active: bool = True


class CustomerStrategyCreate(BaseModel):
    account_id: Optional[int] = None
    symbol: str
    strategy_code: str
    strategy_name: str
    magic: int
    risk_tier: str = "balanced"
    is_enabled: bool = True


class CustomerStrategyUpdate(BaseModel):
    account_id: Optional[int] = None
    symbol: str
    strategy_code: str
    strategy_name: str
    magic: int
    risk_tier: str = "balanced"
    is_enabled: bool = True


class MasterCustomerCreate(BaseModel):
    display_name: str
    access_start_at: Optional[str] = None
    access_end_at: Optional[str] = None
    access_status: str = "active"
    trading_status: str = "enabled"
    subscription_status: str = "active"
    grace_until: Optional[str] = None


class MasterCustomerUpdate(BaseModel):
    display_name: str
    access_start_at: Optional[str] = None
    access_end_at: Optional[str] = None
    access_status: str = "active"
    trading_status: str = "enabled"
    subscription_status: str = "active"
    grace_until: Optional[str] = None


class MasterUserCreate(BaseModel):
    email: EmailStr
    password: str
    display_name: str
    customer_id: int


class MasterCustomerAccountCreate(BaseModel):
    broker_name: str
    account_number: str
    account_label: str
    is_active: bool = True


class MasterCustomerAccountUpdate(BaseModel):
    broker_name: str
    account_number: str
    account_label: str
    is_active: bool = True


class MasterCustomerStrategyCreate(BaseModel):
    account_id: int
    symbol: str
    strategy_code: str
    strategy_name: str
    magic: int
    risk_tier: str = "balanced"
    is_enabled: bool = True


class MasterCustomerStrategyUpdate(BaseModel):
    account_id: int
    symbol: str
    strategy_code: str
    strategy_name: str
    magic: int
    risk_tier: str = "balanced"
    is_enabled: bool = True


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

        user = FAKE_USERS.get(email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return {
            "email": email,
            "role": role,
            "customer_id": user.get("customer_id"),
            "display_name": user.get("display_name", email),
            "access_status": user.get("access_status", "active"),
            "trading_status": user.get("trading_status", "enabled"),
            "subscription_status": user.get("subscription_status", "active"),
        }
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def require_customer(current_user: Dict[str, Any]) -> None:
    if current_user["role"] != "customer":
        raise HTTPException(status_code=403, detail="Not allowed")


def require_master(current_user: Dict[str, Any]) -> None:
    if current_user["role"] != "master":
        raise HTTPException(status_code=403, detail="Not allowed")


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
            strategy_name = strategy.get("strategy_name") or strategy.get("name") or symbol
            strategy_code = strategy.get("strategy_code") or ("btc_core" if symbol == "BTCUSD" else "xau_core")
            magic_value = str(strategy.get("magic", ""))
            strategy_enabled = bool(strategy.get("is_enabled", True)) and bool(setup["enabled"])
            risk_tier = setup["risk_tier"]

            enriched_strategies.append(
                {
                    "id": strategy.get("id"),
                    "account_id": strategy.get("account_id", account_id),
                    "symbol": symbol,
                    "displayName": strategy_name,
                    "name": strategy_name,
                    "strategy_name": strategy_name,
                    "magic": magic_value,
                    "enabled": strategy_enabled,
                    "is_enabled": bool(strategy.get("is_enabled", True)),
                    "riskTier": risk_tier,
                    "risk_tier": risk_tier,
                    "strategyCode": strategy_code,
                    "strategy_code": strategy_code,
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
                "label": f'{account.get("broker_name") or account.get("broker")} • {account["account_number"]}',
                "broker": account.get("broker_name") or account.get("broker"),
                "broker_name": account.get("broker_name") or account.get("broker"),
                "account_label": account.get("account_label") or f'{account.get("broker_name") or account.get("broker")} • {account["account_number"]}',
                "enabled": bool(account.get("is_active", True)),
                "is_active": bool(account.get("is_active", True)),
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


def next_customer_id() -> int:
    ids = [int(customer_id) for customer_id in FAKE_CUSTOMERS.keys()]
    return (max(ids) if ids else 0) + 1


def next_account_id() -> int:
    all_ids: List[int] = []
    for items in FAKE_CUSTOMER_ACCOUNTS.values():
        for item in items:
            all_ids.append(int(item["id"]))
    return (max(all_ids) if all_ids else 0) + 1


def next_strategy_id() -> int:
    all_ids: List[int] = []
    for items in FAKE_ACCOUNT_STRATEGIES.values():
        for item in items:
            if item.get("id") is not None:
                all_ids.append(int(item["id"]))
    return (max(all_ids) if all_ids else 0) + 1


def normalize_risk_tier(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ("conservative", "balanced", "dynamic", "aggressive"):
        raise HTTPException(status_code=422, detail="Invalid risk_tier")
    return normalized


def normalize_access_status(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ("active", "disabled", "expired", "paused"):
        raise HTTPException(status_code=422, detail="Invalid access_status")
    return normalized


def normalize_trading_status(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ("enabled", "disabled", "paused"):
        raise HTTPException(status_code=422, detail="Invalid trading_status")
    return normalized


def normalize_subscription_status(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ("active", "trial", "expired", "cancelled", "grace"):
        raise HTTPException(status_code=422, detail="Invalid subscription_status")
    return normalized


def find_account_for_user(email: str, account_id: int) -> Dict[str, Any]:
    for account in get_user_accounts(email):
        if int(account["id"]) == account_id:
            return account
    raise HTTPException(status_code=404, detail="Account not found")


def find_strategy_for_user(email: str, strategy_id: int) -> Dict[str, Any]:
    for account in get_user_accounts(email):
        account_id = int(account["id"])
        for strategy in get_account_strategies(account_id):
            if int(strategy.get("id", 0)) == strategy_id:
                return strategy
    raise HTTPException(status_code=404, detail="Strategy not found")


def write_audit_log(
    actor_email: str,
    action_type: str,
    message: str,
    target_account_id: Optional[int] = None,
    target_strategy_id: Optional[int] = None,
    target_customer_id: Optional[int] = None,
    target_user_email: Optional[str] = None,
) -> None:
    AUDIT_LOGS.append(
        {
            "created_utc": now_utc_iso(),
            "actor_email": actor_email,
            "action_type": action_type,
            "message": message,
            "target_customer_id": target_customer_id,
            "target_user_email": target_user_email,
            "target_account_id": target_account_id,
            "target_strategy_id": target_strategy_id,
        }
    )


def format_account_payload(account: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(account["id"]),
        "account_number": account["account_number"],
        "broker": account.get("broker_name") or account.get("broker"),
        "broker_name": account.get("broker_name") or account.get("broker"),
        "account_label": account.get("account_label") or f'{account.get("broker_name") or account.get("broker")} • {account["account_number"]}',
        "is_active": bool(account.get("is_active", True)),
    }


def format_strategy_payload(strategy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(strategy["id"]),
        "account_id": strategy.get("account_id"),
        "symbol": strategy["symbol"].upper(),
        "strategy_code": strategy.get("strategy_code") or ("btc_core" if strategy["symbol"].upper() == "BTCUSD" else "xau_core"),
        "strategy_name": strategy.get("strategy_name") or strategy.get("name") or strategy["symbol"].upper(),
        "name": strategy.get("strategy_name") or strategy.get("name") or strategy["symbol"].upper(),
        "magic": str(strategy.get("magic", "")),
        "risk_tier": strategy.get("risk_tier", "balanced"),
        "is_enabled": bool(strategy.get("is_enabled", True)),
    }


def get_customer_user_emails(customer_id: int) -> List[str]:
    emails: List[str] = []
    for email, user in FAKE_USERS.items():
        if user.get("customer_id") == customer_id and user.get("role") == "customer":
            emails.append(email)
    return emails


def get_primary_customer_email(customer_id: int) -> Optional[str]:
    emails = get_customer_user_emails(customer_id)
    return emails[0] if emails else None


def require_customer_owner_email(customer_id: int) -> str:
    email = get_primary_customer_email(customer_id)
    if not email:
        raise HTTPException(status_code=400, detail="Customer has no customer-user login yet")
    return email


def find_customer(customer_id: int) -> Dict[str, Any]:
    customer = FAKE_CUSTOMERS.get(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


def format_customer_payload(customer: Dict[str, Any]) -> Dict[str, Any]:
    customer_id = int(customer["id"])
    user_emails = get_customer_user_emails(customer_id)

    return {
        "id": customer_id,
        "display_name": customer["display_name"],
        "access_start_at": customer.get("access_start_at"),
        "access_end_at": customer.get("access_end_at"),
        "access_status": customer.get("access_status", "active"),
        "trading_status": customer.get("trading_status", "enabled"),
        "subscription_status": customer.get("subscription_status", "active"),
        "grace_until": customer.get("grace_until"),
        "user_count": len(user_emails),
        "user_emails": user_emails,
    }


def sync_customer_status_to_users(customer_id: int) -> None:
    customer = find_customer(customer_id)
    for email, user in FAKE_USERS.items():
        if user.get("customer_id") == customer_id:
            user["display_name"] = customer.get("display_name", user.get("display_name", email))
            user["access_status"] = customer.get("access_status", "active")
            user["trading_status"] = customer.get("trading_status", "enabled")
            user["subscription_status"] = customer.get("subscription_status", "active")


def get_accounts_for_customer(customer_id: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for email in get_customer_user_emails(customer_id):
        for account in get_user_accounts(email):
            rows.append(format_account_payload(account))
    rows.sort(key=lambda x: int(x["id"]))
    return rows


def get_strategies_for_customer(customer_id: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen_ids: set[int] = set()

    for email in get_customer_user_emails(customer_id):
        for account in get_user_accounts(email):
            account_id = int(account["id"])
            for strategy in get_account_strategies(account_id):
                strategy_id = int(strategy.get("id", 0))
                if strategy_id in seen_ids:
                    continue
                seen_ids.add(strategy_id)
                rows.append(format_strategy_payload(strategy))

    rows.sort(key=lambda x: (int(x["account_id"] or 0), x["symbol"], str(x["magic"])))
    return rows


def find_account_for_customer(customer_id: int, account_id: int) -> Tuple[str, Dict[str, Any]]:
    for email in get_customer_user_emails(customer_id):
        for account in get_user_accounts(email):
            if int(account["id"]) == account_id:
                return email, account
    raise HTTPException(status_code=404, detail="Account not found for customer")


def find_strategy_for_customer(customer_id: int, strategy_id: int) -> Tuple[str, Dict[str, Any]]:
    for email in get_customer_user_emails(customer_id):
        for account in get_user_accounts(email):
            account_id = int(account["id"])
            for strategy in get_account_strategies(account_id):
                if int(strategy.get("id", 0)) == strategy_id:
                    return email, strategy
    raise HTTPException(status_code=404, detail="Strategy not found for customer")


def ensure_account_belongs_to_customer(customer_id: int, account_id: int) -> Tuple[str, Dict[str, Any]]:
    return find_account_for_customer(customer_id, account_id)


# =========================================================
# BASIC
# =========================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "version": "6.7.0",
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

    if user.get("role") == "customer":
        access_status = user.get("access_status", "active")
        if access_status != "active":
            raise HTTPException(status_code=403, detail=f"Customer access is {access_status}")

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
        "customer_id": current_user.get("customer_id"),
        "display_name": current_user.get("display_name", email),
        "access_status": current_user.get("access_status", "active"),
        "trading_status": current_user.get("trading_status", "enabled"),
        "subscription_status": current_user.get("subscription_status", "active"),
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


@app.get("/customer/accounts")
def get_customer_accounts(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    require_customer(current_user)
    return [format_account_payload(item) for item in get_user_accounts(current_user["email"])]


@app.post("/customer/accounts")
def create_customer_account(
    data: CustomerAccountCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_customer(current_user)

    email = current_user["email"]
    broker_name = data.broker_name.strip()
    account_number = data.account_number.strip()
    account_label = data.account_label.strip()

    if not broker_name or not account_number or not account_label:
        raise HTTPException(status_code=422, detail="broker_name, account_number and account_label are required")

    accounts = FAKE_CUSTOMER_ACCOUNTS.setdefault(email, [])
    if any(item["account_number"] == account_number for item in accounts):
        raise HTTPException(status_code=400, detail="Account number already exists")

    account_id = next_account_id()
    row = {
        "id": account_id,
        "account_number": account_number,
        "broker": broker_name,
        "broker_name": broker_name,
        "account_label": account_label,
        "is_active": bool(data.is_active),
    }
    accounts.append(row)
    FAKE_ACCOUNT_STRATEGIES.setdefault(account_id, [])
    FAKE_CUSTOMER_SETUP.setdefault(email, {}).setdefault(account_id, {})

    write_audit_log(
        actor_email=email,
        action_type="customer_account_created",
        message=f"Created account {account_number}",
        target_account_id=account_id,
        target_customer_id=current_user.get("customer_id"),
    )

    return format_account_payload(row)


@app.put("/customer/accounts/{account_id}")
def update_customer_account(
    account_id: int,
    data: CustomerAccountUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_customer(current_user)

    email = current_user["email"]
    broker_name = data.broker_name.strip()
    account_number = data.account_number.strip()
    account_label = data.account_label.strip()

    if not broker_name or not account_number or not account_label:
        raise HTTPException(status_code=422, detail="broker_name, account_number and account_label are required")

    account = find_account_for_user(email, account_id)

    for item in get_user_accounts(email):
        if int(item["id"]) != account_id and item["account_number"] == account_number:
            raise HTTPException(status_code=400, detail="Account number already exists")

    account["broker"] = broker_name
    account["broker_name"] = broker_name
    account["account_number"] = account_number
    account["account_label"] = account_label
    account["is_active"] = bool(data.is_active)

    write_audit_log(
        actor_email=email,
        action_type="customer_account_updated",
        message=f"Updated account {account_number}",
        target_account_id=account_id,
        target_customer_id=current_user.get("customer_id"),
    )

    return format_account_payload(account)


@app.delete("/customer/accounts/{account_id}")
def disable_customer_account(
    account_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_customer(current_user)

    email = current_user["email"]
    account = find_account_for_user(email, account_id)
    account["is_active"] = False

    write_audit_log(
        actor_email=email,
        action_type="customer_account_disabled",
        message=f"Disabled account {account['account_number']}",
        target_account_id=account_id,
        target_customer_id=current_user.get("customer_id"),
    )

    return {
        "ok": True,
        "message": "Account disabled",
        "account_id": account_id,
    }


@app.get("/customer/strategies")
def get_customer_strategies(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    require_customer(current_user)

    email = current_user["email"]
    rows: List[Dict[str, Any]] = []

    for account in get_user_accounts(email):
        account_id = int(account["id"])
        for strategy in get_account_strategies(account_id):
            rows.append(format_strategy_payload(strategy))

    rows.sort(key=lambda x: (int(x["account_id"] or 0), x["symbol"], str(x["magic"])))
    return rows


@app.post("/customer/strategies")
def create_customer_strategy(
    data: CustomerStrategyCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_customer(current_user)

    email = current_user["email"]
    account_id = data.account_id
    if account_id is None:
        raise HTTPException(status_code=422, detail="account_id is required")

    ensure_account_access(email, account_id)

    symbol = data.symbol.strip().upper()
    strategy_code = data.strategy_code.strip()
    strategy_name = data.strategy_name.strip()
    magic = str(data.magic).strip()
    risk_tier = normalize_risk_tier(data.risk_tier)

    if not symbol or not strategy_code or not strategy_name or not magic:
        raise HTTPException(status_code=422, detail="symbol, strategy_code, strategy_name and magic are required")

    strategies = FAKE_ACCOUNT_STRATEGIES.setdefault(account_id, [])
    for item in strategies:
        if item["symbol"].upper() == symbol and str(item["magic"]).strip() == magic:
            raise HTTPException(status_code=400, detail="Strategy with symbol and magic already exists for this account")

    strategy_id = next_strategy_id()
    row = {
        "id": strategy_id,
        "account_id": account_id,
        "symbol": symbol,
        "name": strategy_name,
        "strategy_name": strategy_name,
        "strategy_code": strategy_code,
        "magic": magic,
        "risk_tier": risk_tier,
        "is_enabled": bool(data.is_enabled),
    }
    strategies.append(row)

    setup = get_strategy_setup(email, account_id, symbol)
    setup["enabled"] = bool(data.is_enabled)
    setup["risk_tier"] = risk_tier

    write_audit_log(
        actor_email=email,
        action_type="customer_strategy_created",
        message=f"Created strategy {strategy_code} for {symbol}",
        target_account_id=account_id,
        target_strategy_id=strategy_id,
        target_customer_id=current_user.get("customer_id"),
    )

    return format_strategy_payload(row)


@app.put("/customer/strategies/{strategy_id}")
def update_customer_strategy(
    strategy_id: int,
    data: CustomerStrategyUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_customer(current_user)

    email = current_user["email"]
    strategy = find_strategy_for_user(email, strategy_id)

    new_account_id = data.account_id if data.account_id is not None else strategy.get("account_id")
    if new_account_id is None:
        raise HTTPException(status_code=422, detail="account_id is required")

    ensure_account_access(email, int(new_account_id))

    symbol = data.symbol.strip().upper()
    strategy_code = data.strategy_code.strip()
    strategy_name = data.strategy_name.strip()
    magic = str(data.magic).strip()
    risk_tier = normalize_risk_tier(data.risk_tier)

    if not symbol or not strategy_code or not strategy_name or not magic:
        raise HTTPException(status_code=422, detail="symbol, strategy_code, strategy_name and magic are required")

    old_account_id = int(strategy.get("account_id"))
    target_account_id = int(new_account_id)

    if target_account_id != old_account_id:
        old_list = FAKE_ACCOUNT_STRATEGIES.setdefault(old_account_id, [])
        old_list[:] = [item for item in old_list if int(item.get("id", 0)) != strategy_id]
        FAKE_ACCOUNT_STRATEGIES.setdefault(target_account_id, []).append(strategy)

    for item in FAKE_ACCOUNT_STRATEGIES.setdefault(target_account_id, []):
        if int(item.get("id", 0)) == strategy_id:
            continue
        if item["symbol"].upper() == symbol and str(item["magic"]).strip() == magic:
            raise HTTPException(status_code=400, detail="Strategy with symbol and magic already exists for this account")

    strategy["account_id"] = target_account_id
    strategy["symbol"] = symbol
    strategy["name"] = strategy_name
    strategy["strategy_name"] = strategy_name
    strategy["strategy_code"] = strategy_code
    strategy["magic"] = magic
    strategy["risk_tier"] = risk_tier
    strategy["is_enabled"] = bool(data.is_enabled)

    setup = get_strategy_setup(email, target_account_id, symbol)
    setup["enabled"] = bool(data.is_enabled)
    setup["risk_tier"] = risk_tier

    write_audit_log(
        actor_email=email,
        action_type="customer_strategy_updated",
        message=f"Updated strategy {strategy_code} for {symbol}",
        target_account_id=target_account_id,
        target_strategy_id=strategy_id,
        target_customer_id=current_user.get("customer_id"),
    )

    return format_strategy_payload(strategy)


@app.delete("/customer/strategies/{strategy_id}")
def disable_customer_strategy(
    strategy_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_customer(current_user)

    email = current_user["email"]
    strategy = find_strategy_for_user(email, strategy_id)
    strategy["is_enabled"] = False

    account_id = int(strategy.get("account_id"))
    setup = get_strategy_setup(email, account_id, strategy["symbol"])
    setup["enabled"] = False

    write_audit_log(
        actor_email=email,
        action_type="customer_strategy_disabled",
        message=f"Disabled strategy {strategy.get('strategy_code') or strategy.get('name')}",
        target_account_id=account_id,
        target_strategy_id=strategy_id,
        target_customer_id=current_user.get("customer_id"),
    )

    return {
        "ok": True,
        "message": "Strategy disabled",
        "strategy_id": strategy_id,
    }


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

    for strategy in get_account_strategies(account_id):
        if strategy["symbol"].upper() == symbol_upper:
            strategy["risk_tier"] = normalized_risk
            strategy["is_enabled"] = bool(data.enabled)

    return {
        "ok": True,
        "account_id": account_id,
        "symbol": symbol_upper,
        "enabled": setup["enabled"],
        "risk_tier": setup["risk_tier"],
    }


# =========================================================
# MASTER ADMIN (AUTH REQUIRED)
# =========================================================

@app.get("/master/customers")
def master_get_customers(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    require_master(current_user)
    rows = [format_customer_payload(customer) for customer in FAKE_CUSTOMERS.values()]
    rows.sort(key=lambda x: int(x["id"]))
    return rows


@app.post("/master/customers")
def master_create_customer(
    data: MasterCustomerCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)

    display_name = data.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=422, detail="display_name is required")

    customer_id = next_customer_id()
    row = {
        "id": customer_id,
        "display_name": display_name,
        "access_start_at": data.access_start_at,
        "access_end_at": data.access_end_at,
        "access_status": normalize_access_status(data.access_status),
        "trading_status": normalize_trading_status(data.trading_status),
        "subscription_status": normalize_subscription_status(data.subscription_status),
        "grace_until": data.grace_until,
    }
    FAKE_CUSTOMERS[customer_id] = row

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_created",
        message=f"Created customer {display_name}",
        target_customer_id=customer_id,
    )

    return format_customer_payload(row)


@app.get("/master/customers/{customer_id}")
def master_get_customer(
    customer_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    customer = find_customer(customer_id)
    return format_customer_payload(customer)


@app.put("/master/customers/{customer_id}")
def master_update_customer(
    customer_id: int,
    data: MasterCustomerUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)

    customer = find_customer(customer_id)
    display_name = data.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=422, detail="display_name is required")

    customer["display_name"] = display_name
    customer["access_start_at"] = data.access_start_at
    customer["access_end_at"] = data.access_end_at
    customer["access_status"] = normalize_access_status(data.access_status)
    customer["trading_status"] = normalize_trading_status(data.trading_status)
    customer["subscription_status"] = normalize_subscription_status(data.subscription_status)
    customer["grace_until"] = data.grace_until

    sync_customer_status_to_users(customer_id)

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_updated",
        message=f"Updated customer {display_name}",
        target_customer_id=customer_id,
    )

    return format_customer_payload(customer)


@app.post("/master/users")
def master_create_customer_user(
    data: MasterUserCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)

    email = data.email.strip().lower()
    password = data.password.strip()
    display_name = data.display_name.strip()
    customer_id = int(data.customer_id)

    if not password or not display_name:
        raise HTTPException(status_code=422, detail="password and display_name are required")

    if email in FAKE_USERS:
        raise HTTPException(status_code=400, detail="User email already exists")

    customer = find_customer(customer_id)

    FAKE_USERS[email] = {
        "password": password,
        "role": "customer",
        "customer_id": customer_id,
        "display_name": display_name,
        "access_status": customer.get("access_status", "active"),
        "trading_status": customer.get("trading_status", "enabled"),
        "subscription_status": customer.get("subscription_status", "active"),
    }
    FAKE_CUSTOMER_ACCOUNTS.setdefault(email, [])
    if not isinstance(FAKE_CUSTOMER_ACCOUNTS[email], list):
        FAKE_CUSTOMER_ACCOUNTS[email] = []

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_user_created",
        message=f"Created customer user {email}",
        target_customer_id=customer_id,
        target_user_email=email,
    )

    return {
        "ok": True,
        "email": email,
        "role": "customer",
        "customer_id": customer_id,
        "display_name": display_name,
    }


@app.get("/master/customers/{customer_id}/accounts")
def master_get_customer_accounts(
    customer_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    require_master(current_user)
    find_customer(customer_id)
    return get_accounts_for_customer(customer_id)


@app.post("/master/customers/{customer_id}/accounts")
def master_create_customer_account(
    customer_id: int,
    data: MasterCustomerAccountCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    find_customer(customer_id)

    owner_email = require_customer_owner_email(customer_id)
    broker_name = data.broker_name.strip()
    account_number = data.account_number.strip()
    account_label = data.account_label.strip()

    if not broker_name or not account_number or not account_label:
        raise HTTPException(status_code=422, detail="broker_name, account_number and account_label are required")

    accounts = FAKE_CUSTOMER_ACCOUNTS.setdefault(owner_email, [])
    if any(item["account_number"] == account_number for item in accounts):
        raise HTTPException(status_code=400, detail="Account number already exists")

    account_id = next_account_id()
    row = {
        "id": account_id,
        "account_number": account_number,
        "broker": broker_name,
        "broker_name": broker_name,
        "account_label": account_label,
        "is_active": bool(data.is_active),
    }
    accounts.append(row)
    FAKE_ACCOUNT_STRATEGIES.setdefault(account_id, [])
    FAKE_CUSTOMER_SETUP.setdefault(owner_email, {}).setdefault(account_id, {})

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_account_created",
        message=f"Created customer account {account_number}",
        target_customer_id=customer_id,
        target_account_id=account_id,
        target_user_email=owner_email,
    )

    return format_account_payload(row)


@app.put("/master/customers/{customer_id}/accounts/{account_id}")
def master_update_customer_account(
    customer_id: int,
    account_id: int,
    data: MasterCustomerAccountUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    find_customer(customer_id)

    owner_email, account = find_account_for_customer(customer_id, account_id)

    broker_name = data.broker_name.strip()
    account_number = data.account_number.strip()
    account_label = data.account_label.strip()

    if not broker_name or not account_number or not account_label:
        raise HTTPException(status_code=422, detail="broker_name, account_number and account_label are required")

    for item in get_user_accounts(owner_email):
        if int(item["id"]) != account_id and item["account_number"] == account_number:
            raise HTTPException(status_code=400, detail="Account number already exists")

    account["broker"] = broker_name
    account["broker_name"] = broker_name
    account["account_number"] = account_number
    account["account_label"] = account_label
    account["is_active"] = bool(data.is_active)

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_account_updated",
        message=f"Updated customer account {account_number}",
        target_customer_id=customer_id,
        target_account_id=account_id,
        target_user_email=owner_email,
    )

    return format_account_payload(account)


@app.delete("/master/customers/{customer_id}/accounts/{account_id}")
def master_disable_customer_account(
    customer_id: int,
    account_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    find_customer(customer_id)

    owner_email, account = find_account_for_customer(customer_id, account_id)
    account["is_active"] = False

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_account_disabled",
        message=f"Disabled customer account {account['account_number']}",
        target_customer_id=customer_id,
        target_account_id=account_id,
        target_user_email=owner_email,
    )

    return {
        "ok": True,
        "message": "Account disabled",
        "account_id": account_id,
    }


@app.get("/master/customers/{customer_id}/strategies")
def master_get_customer_strategies(
    customer_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    require_master(current_user)
    find_customer(customer_id)
    return get_strategies_for_customer(customer_id)


@app.post("/master/customers/{customer_id}/strategies")
def master_create_customer_strategy(
    customer_id: int,
    data: MasterCustomerStrategyCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    find_customer(customer_id)

    owner_email, _account = ensure_account_belongs_to_customer(customer_id, data.account_id)

    symbol = data.symbol.strip().upper()
    strategy_code = data.strategy_code.strip()
    strategy_name = data.strategy_name.strip()
    magic = str(data.magic).strip()
    risk_tier = normalize_risk_tier(data.risk_tier)

    if not symbol or not strategy_code or not strategy_name or not magic:
        raise HTTPException(status_code=422, detail="symbol, strategy_code, strategy_name and magic are required")

    strategies = FAKE_ACCOUNT_STRATEGIES.setdefault(data.account_id, [])
    for item in strategies:
        if item["symbol"].upper() == symbol and str(item["magic"]).strip() == magic:
            raise HTTPException(status_code=400, detail="Strategy with symbol and magic already exists for this account")

    strategy_id = next_strategy_id()
    row = {
        "id": strategy_id,
        "account_id": data.account_id,
        "symbol": symbol,
        "name": strategy_name,
        "strategy_name": strategy_name,
        "strategy_code": strategy_code,
        "magic": magic,
        "risk_tier": risk_tier,
        "is_enabled": bool(data.is_enabled),
    }
    strategies.append(row)

    setup = get_strategy_setup(owner_email, data.account_id, symbol)
    setup["enabled"] = bool(data.is_enabled)
    setup["risk_tier"] = risk_tier

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_strategy_created",
        message=f"Created strategy {strategy_code} for {symbol}",
        target_customer_id=customer_id,
        target_account_id=data.account_id,
        target_strategy_id=strategy_id,
        target_user_email=owner_email,
    )

    return format_strategy_payload(row)


@app.put("/master/customers/{customer_id}/strategies/{strategy_id}")
def master_update_customer_strategy(
    customer_id: int,
    strategy_id: int,
    data: MasterCustomerStrategyUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    find_customer(customer_id)

    owner_email, strategy = find_strategy_for_customer(customer_id, strategy_id)
    target_owner_email, _target_account = ensure_account_belongs_to_customer(customer_id, data.account_id)

    symbol = data.symbol.strip().upper()
    strategy_code = data.strategy_code.strip()
    strategy_name = data.strategy_name.strip()
    magic = str(data.magic).strip()
    risk_tier = normalize_risk_tier(data.risk_tier)

    if not symbol or not strategy_code or not strategy_name or not magic:
        raise HTTPException(status_code=422, detail="symbol, strategy_code, strategy_name and magic are required")

    old_account_id = int(strategy.get("account_id"))
    target_account_id = int(data.account_id)

    if target_account_id != old_account_id:
        old_list = FAKE_ACCOUNT_STRATEGIES.setdefault(old_account_id, [])
        old_list[:] = [item for item in old_list if int(item.get("id", 0)) != strategy_id]
        FAKE_ACCOUNT_STRATEGIES.setdefault(target_account_id, []).append(strategy)

    for item in FAKE_ACCOUNT_STRATEGIES.setdefault(target_account_id, []):
        if int(item.get("id", 0)) == strategy_id:
            continue
        if item["symbol"].upper() == symbol and str(item["magic"]).strip() == magic:
            raise HTTPException(status_code=400, detail="Strategy with symbol and magic already exists for this account")

    strategy["account_id"] = target_account_id
    strategy["symbol"] = symbol
    strategy["name"] = strategy_name
    strategy["strategy_name"] = strategy_name
    strategy["strategy_code"] = strategy_code
    strategy["magic"] = magic
    strategy["risk_tier"] = risk_tier
    strategy["is_enabled"] = bool(data.is_enabled)

    setup = get_strategy_setup(target_owner_email, target_account_id, symbol)
    setup["enabled"] = bool(data.is_enabled)
    setup["risk_tier"] = risk_tier

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_strategy_updated",
        message=f"Updated strategy {strategy_code} for {symbol}",
        target_customer_id=customer_id,
        target_account_id=target_account_id,
        target_strategy_id=strategy_id,
        target_user_email=owner_email,
    )

    return format_strategy_payload(strategy)


@app.delete("/master/customers/{customer_id}/strategies/{strategy_id}")
def master_disable_customer_strategy(
    customer_id: int,
    strategy_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    find_customer(customer_id)

    owner_email, strategy = find_strategy_for_customer(customer_id, strategy_id)
    strategy["is_enabled"] = False

    account_id = int(strategy.get("account_id"))
    setup = get_strategy_setup(owner_email, account_id, strategy["symbol"])
    setup["enabled"] = False

    write_audit_log(
        actor_email=current_user["email"],
        action_type="master_customer_strategy_disabled",
        message=f"Disabled strategy {strategy.get('strategy_code') or strategy.get('name')}",
        target_customer_id=customer_id,
        target_account_id=account_id,
        target_strategy_id=strategy_id,
        target_user_email=owner_email,
    )

    return {
        "ok": True,
        "message": "Strategy disabled",
        "strategy_id": strategy_id,
    }


@app.get("/master/audit_logs")
def master_get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    require_master(current_user)
    rows = sorted(AUDIT_LOGS, key=lambda x: x["created_utc"], reverse=True)
    return {
        "ok": True,
        "count": len(rows[:limit]),
        "items": rows[:limit],
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
