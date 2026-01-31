from fastapi import Header, HTTPException
from app.config import get_settings


def require_api_key(x_api_key: str = Header(default="", alias="x-api-key")) -> None:
    settings = get_settings()
    if not x_api_key or x_api_key.strip() != settings.honeypot_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid API key")
