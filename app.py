from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Signal(BaseModel):
    symbol: str
    side: str
    price: float
    timestamp: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


@app.get("/")
def root():
    return {
        "status": "running",
        "service": "signal-agent-api",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": datetime.utcnow().isoformat()
    }


@app.post("/login")
async def login(data: LoginRequest):
    if data.email == "test@test.com" and data.password == "123456":
        return {
            "success": True,
            "token": "demo_token_123",
            "user": {
                "id": "1",
                "email": data.email
            }
        }

    return {
        "success": False,
        "message": "Invalid email or password"
    }


@app.post("/signal")
async def receive_signal(signal: Signal):
    print("----- SIGNAL RECEIVED -----")
    print(f"Symbol: {signal.symbol}")
    print(f"Side: {signal.side}")
    print(f"Price: {signal.price}")
    print(f"Time: {signal.timestamp}")

    return {
        "status": "received",
        "symbol": signal.symbol,
        "side": signal.side,
        "price": signal.price
    }


@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()

    print("----- WEBHOOK RECEIVED -----")
    print(data)

    return {
        "status": "ok",
        "data": data
    }
