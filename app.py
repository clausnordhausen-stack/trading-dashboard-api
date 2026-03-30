from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt, JWTError
import sqlite3
import os

# =========================================================
# CONFIG
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = os.getenv("DB_PATH", "app.db")

app = FastAPI(title="Signal Agent API", version="6.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# =========================================================
# DATABASE
# =========================================================

def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # USERS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'customer',
        created_at TEXT
    )
    """)

    # ACCOUNTS (USER-OWNED)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        account_number TEXT,
        broker TEXT,
        created_at TEXT
    )
    """)

    # STRATEGIES (EAs)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS strategies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        symbol TEXT,
        magic INTEGER
    )
    """)

    # ACCOUNT <-> STRATEGY LINK
    cur.execute("""
    CREATE TABLE IF NOT EXISTS account_strategies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER,
        strategy_id INTEGER
    )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# MODELS
# =========================================================

class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str


class AccountCreate(BaseModel):
    account_number: str
    broker: str


class StrategyAssign(BaseModel):
    account_id: int
    strategy_id: int


# =========================================================
# AUTH
# =========================================================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, email FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=401, detail="User not found")

        return {"id": row[0], "email": row[1]}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# =========================================================
# AUTH ROUTES
# =========================================================

@app.post("/register")
def register(data: RegisterRequest):
    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)",
            (data.email, data.password, datetime.utcnow().isoformat())
        )
        conn.commit()
    except:
        raise HTTPException(status_code=400, detail="User already exists")

    return {"status": "registered"}


@app.post("/login")
def login(data: LoginRequest):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, password FROM users WHERE email=?",
        (data.email,)
    )
    row = cur.fetchone()
    conn.close()

    if not row or row[1] != data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"user_id": row[0]})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": row[0]
    }


# =========================================================
# ACCOUNT MANAGEMENT
# =========================================================

@app.post("/accounts")
def create_account(data: AccountCreate, user=Depends(get_current_user)):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO accounts (user_id, account_number, broker, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        user["id"],
        data.account_number,
        data.broker,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()

    return {"status": "account_created"}


@app.get("/accounts")
def get_accounts(user=Depends(get_current_user)):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, account_number, broker
        FROM accounts
        WHERE user_id=?
    """, (user["id"],))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "account_number": r[1],
            "broker": r[2]
        }
        for r in rows
    ]


# =========================================================
# STRATEGY MANAGEMENT
# =========================================================

@app.get("/strategies")
def get_strategies():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, name, symbol, magic FROM strategies")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "name": r[1],
            "symbol": r[2],
            "magic": r[3]
        }
        for r in rows
    ]


@app.post("/assign-strategy")
def assign_strategy(data: StrategyAssign, user=Depends(get_current_user)):
    conn = get_conn()
    cur = conn.cursor()

    # Ownership check
    cur.execute("SELECT id FROM accounts WHERE id=? AND user_id=?",
                (data.account_id, user["id"]))
    if not cur.fetchone():
        raise HTTPException(status_code=403, detail="Not your account")

    cur.execute("""
        INSERT INTO account_strategies (account_id, strategy_id)
        VALUES (?, ?)
    """, (data.account_id, data.strategy_id))

    conn.commit()
    conn.close()

    return {"status": "assigned"}


@app.get("/account-strategies/{account_id}")
def get_account_strategies(account_id: int, user=Depends(get_current_user)):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT s.id, s.name, s.symbol, s.magic
        FROM account_strategies a
        JOIN strategies s ON s.id = a.strategy_id
        WHERE a.account_id=?
    """, (account_id,))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "name": r[1],
            "symbol": r[2],
            "magic": r[3]
        }
        for r in rows
    ]


# =========================================================
# HEALTH
# =========================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "version": "6.1.0",
        "service": "signal-agent-api"
    }
