import os
from fastapi import HTTPException, Request

API_KEY = os.getenv("API_KEY", "")

def assert_api_key(request: Request):
    key = request.headers.get("X-Api-Key")
    if not API_KEY or key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
