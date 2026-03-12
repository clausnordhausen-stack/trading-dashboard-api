from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import os

app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY", "claus-2026-xau-01!")

SYMBOL_COOLDOWN_MIN = int(os.getenv("SYMBOL_COOLDOWN_MIN", 30))
PENDING_TTL_SEC = int(os.getenv("PENDING_TTL_SEC", 120))

# ------------------------------
# MODELS
# ------------------------------

class TVSignal(BaseModel):
    key: str
    symbol: str
    action: str
    id: str | None = None
    ts: str | None = None


# ------------------------------
# STATE
# ------------------------------

STATE = {}


def now():
    return datetime.now(timezone.utc)


def norm_symbol(s):
    return s.upper().strip()


def norm_action(a):
    return a.upper().strip()


# ------------------------------
# ROOT
# ------------------------------

@app.get("/")
def root():
    return {"status": "Signal Agent API running"}


# ------------------------------
# TV SIGNAL INGEST
# ------------------------------

@app.post("/tv")
def tv_signal(sig: TVSignal):

    if sig.key != SECRET_KEY:
        raise HTTPException(status_code=403, detail="invalid key")

    symbol = norm_symbol(sig.symbol)
    action = norm_action(sig.action)

    if action not in ["BUY", "SELL"]:
        raise HTTPException(status_code=400, detail="invalid action")

    state = STATE.get(symbol)

    now_time = now()

    # create state if missing
    if not state:
        STATE[symbol] = {
            "pending": None,
            "cooldown_until": None,
            "last_signal_id": None
        }
        state = STATE[symbol]

    # 30 MIN COOLDOWN
    if state["cooldown_until"]:
        if now_time < state["cooldown_until"]:
            return {"status": "cooldown_active"}

    # DUPLICATE SIGNAL BLOCK
    if sig.id and sig.id == state["last_signal_id"]:
        return {"status": "duplicate_blocked"}

    # CREATE PENDING SIGNAL
    pending = {
        "symbol": symbol,
        "action": action,
        "id": sig.id,
        "created": now_time.isoformat()
    }

    state["pending"] = pending
    state["last_signal_id"] = sig.id

    return {"status": "signal_received", "symbol": symbol}


# ------------------------------
# EA POLL LATEST SIGNAL
# ------------------------------

@app.get("/latest")
def latest(symbol: str, account: str = "", magic: str = ""):

    symbol = norm_symbol(symbol)

    state = STATE.get(symbol)

    if not state:
        return {"signal": None}

    pending = state["pending"]

    if not pending:
        return {"signal": None}

    created = datetime.fromisoformat(pending["created"])

    # EXPIRE OLD SIGNAL
    if now() - created > timedelta(seconds=PENDING_TTL_SEC):
        state["pending"] = None
        return {"signal": None}

    return {
        "signal": {
            "symbol": pending["symbol"],
            "action": pending["action"]
        },
        "updated_utc": pending["created"]
    }


# ------------------------------
# EA ACK TRADE EXECUTION
# ------------------------------

@app.post("/ack")
def ack(symbol: str, updated_utc: str, account: str = "", magic: str = ""):

    symbol = norm_symbol(symbol)

    state = STATE.get(symbol)

    if not state:
        return {"status": "no_state"}

    pending = state["pending"]

    if not pending:
        return {"status": "no_pending"}

    if pending["created"] != updated_utc:
        return {"status": "signal_mismatch"}

    # CLEAR PENDING
    state["pending"] = None

    # START 30 MIN COOLDOWN
    state["cooldown_until"] = now() + timedelta(minutes=SYMBOL_COOLDOWN_MIN)

    return {"status": "acknowledged"}
