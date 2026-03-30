from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import app as fastapi_app  # falls du app.py nutzt

# OPTIONAL: wenn du alles in main.py haben willst, dann diesen Block nutzen
app = FastAPI(title="Signal Agent API", version="6.0.0")

# -------------------------------
# CORS (Flutter / Web wichtig!)
# -------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später einschränken
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# ROOT
# -------------------------------
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "version": "6.0.0"
    }


# =========================================================
# 🔐 LOGIN SYSTEM
# =========================================================

from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import jwt
import os

SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str


# 🔑 Dummy User DB (ersetzen später!)
FAKE_USERS = {
    "test@test.com": {
        "password": "123456",
        "role": "customer"
    }
}


@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest):
    user = FAKE_USERS.get(data.email)

    if not user or user["password"] != data.password:
        return {"error": "invalid credentials"}

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    token = jwt.encode(
        {
            "sub": data.email,
            "role": user["role"],
            "exp": expire
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# =========================================================
# 👤 USER INFO (/me)
# =========================================================

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {
        "email": user["sub"],
        "role": user.get("role", "customer"),
        "display_name": user["sub"],
        "access_status": "active",
        "trading_status": "enabled",
        "subscription_status": "active"
    }


# =========================================================
# 📊 CUSTOMER ACCOUNTS
# =========================================================

@app.get("/accounts")
def get_accounts(user=Depends(get_current_user)):
    # später DB
    return [
        {
            "id": 1,
            "account_number": "10001",
            "broker": "IC Markets"
        },
        {
            "id": 2,
            "account_number": "10002",
            "broker": "FTMO"
        }
    ]


@app.get("/accounts/{account_id}/strategies")
def get_strategies(account_id: int, user=Depends(get_current_user)):
    return [
        {
            "symbol": "XAUUSD",
            "name": "Gold Core",
            "magic": "61001"
        },
        {
            "symbol": "BTCUSD",
            "name": "BTC Core",
            "magic": "61002"
        }
    ]


# =========================================================
# 🚀 HEALTH
# =========================================================

@app.get("/health")
def health():
    return {"status": "ok"}
