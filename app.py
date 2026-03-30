from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import os

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

# =========================================================
# APP
# =========================================================

app = FastAPI(title="Signal Agent API", version="6.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später absichern
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =========================================================
# DUMMY DATA
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

# =========================================================
# MODELS
# =========================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str


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
    if symbol == "XAUUSD":
        return "GREEN"
    if symbol == "BTCUSD":
        return "GREEN"
    return "YELLOW"


# =========================================================
# BASIC
# =========================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "version": "6.1.0",
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
# CUSTOMER ACCOUNTS
# =========================================================

@app.get("/accounts")
def get_accounts(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    email = current_user["email"]
    return get_user_accounts(email)


@app.get("/accounts/{account_id}/strategies")
def get_strategies(
    account_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    accounts = get_user_accounts(current_user["email"])
    allowed_ids = {int(item["id"]) for item in accounts}

    if account_id not in allowed_ids and current_user["role"] != "master":
        raise HTTPException(status_code=404, detail="Account not found")

    return get_account_strategies(account_id)


# =========================================================
# DASHBOARD / MONITORING ENDPOINTS EXPECTED BY FLUTTER
# =========================================================

@app.get("/status/system_overview")
def system_overview(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    gate_level = infer_gate_level(symbol)

    return {
        "ok": True,
        "server_time_utc": now_utc_iso(),
        "filters": {
            "symbol": symbol.upper(),
            "account": account,
            "magic": magic,
        },
        "heartbeat": {
            "ok": True,
            "connected_count": 1,
            "items": [
                {
                    "symbol": symbol.upper(),
                    "account": account,
                    "magic": magic,
                    "connected": True,
                    "last_seen_utc": now_utc_iso(),
                    "ea_name": f"{symbol.upper()} Core EA",
                    "version": "1.0.0",
                    "status": "alive",
                }
            ],
        },
        "controls": {
            "paused": False,
            "allow_new_entries": True,
            "risk_multiplier": 1.0,
            "symbol": symbol.upper(),
            "source": "dummy_backend",
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
            "symbol": symbol.upper(),
            "gate_level": gate_level,
            "allow_new_entries": True,
            "risk_multiplier": 1.0,
            "paused": False,
            "controls": {
                "paused": False,
                "allow_new_entries": True,
                "risk_multiplier": 1.0,
            },
            "auto_gate": {
                "gate_level": gate_level,
                "allow_new_entries": True,
                "risk_multiplier": 1.0,
                "reasons": ["NORMAL"],
            },
            "risk_engine": {
                "enabled": True,
                "allow_new_entries": True,
                "risk_level": "GREEN",
                "daily_pnl": 0.0,
                "daily_r": 0.0,
                "daily_trades": 0,
                "limits": {
                    "daily_loss_cap_usd": 250.0,
                    "daily_r_cap": -5.0,
                    "daily_max_trades": 10,
                },
                "reasons": ["NORMAL"],
            },
            "reasons": ["NORMAL"],
        },
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": True,
            "risk_level": "GREEN",
            "daily_pnl": 0.0,
            "daily_r": 0.0,
            "daily_trades": 0,
            "limits": {
                "daily_loss_cap_usd": 250.0,
                "daily_r_cap": -5.0,
                "daily_max_trades": 10,
            },
            "reasons": ["NORMAL"],
        },
    }


@app.get("/status/risk_engine")
def status_risk_engine(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "ok": True,
        "filters": {
            "symbol": symbol.upper(),
            "account": account,
            "magic": magic,
        },
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": True,
            "risk_level": "GREEN",
            "daily_pnl": 0.0,
            "daily_r": 0.0,
            "daily_trades": 0,
            "limits": {
                "daily_loss_cap_usd": 250.0,
                "daily_r_cap": -5.0,
                "daily_max_trades": 10,
            },
            "reasons": ["NORMAL"],
        },
    }


@app.get("/status/gate_combo")
def gate_combo(
    symbol: str = Query(...),
    account: str = Query(...),
    magic: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    gate_level = infer_gate_level(symbol)

    return {
        "ok": True,
        "symbol": symbol.upper(),
        "gate_level": gate_level,
        "allow_new_entries": True,
        "risk_multiplier": 1.0,
        "paused": False,
        "controls": {
            "paused": False,
            "allow_new_entries": True,
            "risk_multiplier": 1.0,
            "symbol": symbol.upper(),
            "source": "dummy_backend",
        },
        "auto_gate": {
            "gate_level": gate_level,
            "allow_new_entries": True,
            "risk_multiplier": 1.0,
            "reasons": ["NORMAL"],
        },
        "risk_engine": {
            "enabled": True,
            "allow_new_entries": True,
            "risk_level": "GREEN",
            "daily_pnl": 0.0,
            "daily_r": 0.0,
            "daily_trades": 0,
            "limits": {
                "daily_loss_cap_usd": 250.0,
                "daily_r_cap": -5.0,
                "daily_max_trades": 10,
            },
            "reasons": ["NORMAL"],
        },
        "reasons": ["NORMAL"],
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
    return {
        "ok": True,
        "has_signal": False,
        "blocked": False,
        "symbol": symbol.upper(),
        "controls": {
            "paused": False,
            "allow_new_entries": True,
            "risk_multiplier": 1.0,
        },
        "gate": {
            "gate_level": infer_gate_level(symbol),
            "allow_new_entries": True,
            "risk_multiplier": 1.0,
        },
        "filter": {
            "approved": True,
            "reason": "NO_SIGNAL",
            "score": None,
        },
        "signal": None,
    }


# =========================================================
# DEBUG ENDPOINTS EXPECTED BY FLUTTER
# =========================================================

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


# =========================================================
# OPTIONAL PLACEHOLDERS FOR LATER
# =========================================================

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
