import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    honeypot_api_key: str
    environment: str = "production"


def get_settings() -> Settings:
    api_key = os.getenv("HONEYPOT_API_KEY", "").strip()
    env = os.getenv("ENVIRONMENT", "production").strip()

    if not api_key:
        # On Render you WILL set this in Environment Variables.
        # Locally you can export it.
        raise RuntimeError("Missing env var: HONEYPOT_API_KEY")

    return Settings(honeypot_api_key=api_key, environment=env)
