"""
Astrotag — Main Application Index Entrypoint
Exports the FastAPI app from main.py for Vercel, WSGI/ASGI runners, and local execution.
"""
from main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
