# main.py

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app:app",   # wichtig: app.py -> app Objekt
        host="0.0.0.0",
        port=10000,
        reload=True
    )
