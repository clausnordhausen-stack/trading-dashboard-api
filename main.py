import os
import uvicorn

# Wichtig: importiert deine FastAPI-Instanz aus app.py
from app import app


def run():
    """
    Lokaler Start (z.B. python main.py)
    """
    port = int(os.getenv("PORT", 10000))
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=port,
        reload=True  # lokal praktisch, auf Render ignoriert
    )


if __name__ == "__main__":
    run()
