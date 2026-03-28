import os
import uvicorn


def run():
    port = int(os.getenv("PORT", "10000"))
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )


if __name__ == "__main__":
    run()
