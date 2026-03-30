from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import jwt, JWTError
import os

# =========================================================
# 🚀 APP INIT (WICHTIG: KEIN SELF IMPORT!)
# =========================================================

app = FastAPI(title="Signal Agent API", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später absichern
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# ⚙️ CONFIG
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =========================================================
# 🧠 FAKE USER DB (ERSETZEN SPÄTER DURCH ECHTE DB)
# =========================================================

FAKE_USERS = {
    "test@test.com": {
        "password": "123456",
        "role": "customer"
    }
}

# =========================================================
# 📦 MODELS
# =========================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str


# =========================================================
# 🔐 AUTH HELPERS
# =========================================================

def create_token(email: str, role: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    return jwt.encode(
        {
            "sub": email,
            "role": role,
            "exp": expire
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# =========================================================
# 🏠 ROOT / HEALTH
# =========================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "signal-agent-api",
        "version": "6.0.0"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# =========================================================
# 🔐 LOGIN
# =========================================================

@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest):
    user = FAKE_USERS.get(data.email)

    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(data.email, user["role"])

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# =========================================================
# 👤 USER INFO
# =========================================================

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
