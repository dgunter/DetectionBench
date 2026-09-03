"""Runtime settings.

Secrets come from systemd credentials (``$CREDENTIALS_DIRECTORY/<name>``) in
production and from ``DETECTIONBENCH_<NAME>`` environment variables in local
development. Nothing here is ever logged or returned to a client.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def read_credential(name: str) -> str | None:
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        path = Path(cred_dir) / name
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
    value = os.environ.get(f"DETECTIONBENCH_{name.upper()}", "").strip()
    return value or None


@dataclass(frozen=True)
class Settings:
    access_token: str | None
    session_secret: str | None
    anthropic_api_key: str | None
    secure_cookies: bool
    session_ttl_seconds: int = 24 * 60 * 60
    max_body_bytes: int = 64 * 1024
    # Token-verify endpoint: per-IP sliding window.
    verify_rate_limit: int = 10
    verify_rate_window_seconds: int = 60
    # LLM endpoints: per-IP sliding window plus a global hourly budget.
    llm_rate_limit: int = 20
    llm_rate_window_seconds: int = 60
    llm_hourly_budget: int = 200
    llm_timeout_seconds: float = 60.0
    llm_model: str = "claude-opus-5"

    @property
    def auth_configured(self) -> bool:
        return bool(self.access_token and self.session_secret)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        access_token=read_credential("access_token"),
        session_secret=read_credential("session_secret"),
        anthropic_api_key=read_credential("anthropic_api_key"),
        secure_cookies=os.environ.get("DETECTIONBENCH_INSECURE_COOKIES", "") != "1",
    )
