from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

app = FastAPI()

SECRET = "supersecret123"

# -----------------------------
# In-Memory State
# -----------------------------

STATE: Dict[str, Dict[str, Any]] = {}
HEARTBEATS: Dict[str, Dict[str, Any]] = {}

# -----------------------------
# Models
# -----------------------------

class TVSignal(BaseModel):
    key: str
    symbol: str
    action: str
    price: float | None = None
    id: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


# -----------------------------
# Helpers
# -----------------------------

def now():
    return datetime.now(timezone.utc)


def norm_symbol(s: str):
    return (s or "").strip().upper()


# -----------------------------
# Health
# -----------------------------

@app.get("/")
def root():
    return {
        "status": "signal agent running",
        "time": now().isoformat()
    }


# -----------------------------
# Login (Demo)
# -----------------------------

@app.post("/login")
async def login(data: LoginRequest):

    email = data.email.strip()
    password = data.password.strip()

    if email == "test@test.com" and password == "123456":
        return {
            "success": True,
            "token": "demo_token_123",
            "user": {
                "id": "1",
                "email": email
            }
        }

    raise HTTPException(status_code=401, detail="Invalid login")


# -----------------------------
# TradingView Webhook
# -----------------------------

@app.post("/tv")
async def tv(signal: TVSignal):

    if signal.key != SECRET:
        raise HTTPException(status_code=401, detail="Invalid key")

    symbol = norm_symbol(signal.symbol)

    STATE[symbol] = {
        "symbol": symbol,
        "action": signal.action,
        "price": signal.price,
        "updated_utc": now().isoformat(),
        "acknowledged": False
    }

    return {
        "status": "stored",
        "symbol": symbol
    }


# optional alternative webhook path

@app.post("/webhook")
async def webhook(request: Request):

    data = await request.json()

    if data.get("key") != SECRET:
        raise HTTPException(status_code=401)

    symbol = norm_symbol(data.get("symbol"))

    STATE[symbol] = {
        "symbol": symbol,
        "action": data.get("action"),
        "price": data.get("price"),
        "updated_utc": now().isoformat(),
        "acknowledged": False
    }

    return {"status": "ok"}


# -----------------------------
# Latest signal for EA
# -----------------------------

@app.get("/latest")
def latest(symbol: str):

    symbol = norm_symbol(symbol)

    if symbol not in STATE:
        return {"signal": None}

    return STATE[symbol]


# -----------------------------
# ACK (EA confirms execution)
# -----------------------------

@app.post("/ack")
def ack(symbol: str):

    symbol = norm_symbol(symbol)

    if symbol not in STATE:
        raise HTTPException(status_code=404)

    STATE[symbol]["acknowledged"] = True

    return {"status": "acknowledged"}


# -----------------------------
# Gate status for dashboard
# -----------------------------

@app.get("/status/gate_combo")
def gate_combo(symbol: str):

    symbol = norm_symbol(symbol)

    state = STATE.get(symbol)

    return {
        "symbol": symbol,
        "has_signal": state is not None,
        "acknowledged": state["acknowledged"] if state else False,
        "time": now().isoformat()
    }


# -----------------------------
# Debug state
# -----------------------------

@app.get("/debug/state")
def debug_state(symbol: str | None = None):

    if symbol:
        symbol = norm_symbol(symbol)
        return STATE.get(symbol, {})

    return STATE


# -----------------------------
# EA Heartbeat
# -----------------------------

@app.post("/heartbeat")
async def heartbeat(request: Request):

    data = await request.json()

    symbol = norm_symbol(data.get("symbol"))
    account = data.get("account")

    HEARTBEATS[symbol] = {
        "symbol": symbol,
        "account": account,
        "last_seen": now()
    }

    return {"status": "ok"}


@app.get("/heartbeat/status")
def heartbeat_status(symbol: str):

    symbol = norm_symbol(symbol)

    hb = HEARTBEATS.get(symbol)

    if not hb:
        return {
            "symbol": symbol,
            "online": False
        }

    delta = now() - hb["last_seen"]

    return {
        "symbol": symbol,
        "online": delta < timedelta(seconds=30),
        "last_seen": hb["last_seen"].isoformat()
    }
