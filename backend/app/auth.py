"""Access-token gate and stateless signed session cookie.

One shared secret, compared in constant time. The session cookie is
``<expiry>.<hmac-sha256(secret, expiry)>``: nothing server-side to look up,
so logout just clears the cookie and a stolen cookie stays valid until it
expires. That trade-off is deliberate for v1.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import HTTPException, Request

from app.config import Settings

COOKIE_NAME = "db_session"


def _sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_access_token(settings: Settings, submitted: str) -> bool:
    if not settings.access_token:
        return False
    return hmac.compare_digest(submitted.encode("utf-8"), settings.access_token.encode("utf-8"))


def make_session_cookie(settings: Settings, now: float | None = None) -> str:
    assert settings.session_secret
    expiry = str(int((now if now is not None else time.time()) + settings.session_ttl_seconds))
    return f"{expiry}.{_sign(settings.session_secret, expiry)}"


def verify_session_cookie(settings: Settings, value: str | None, now: float | None = None) -> bool:
    if not value or not settings.session_secret:
        return False
    expiry, sep, signature = value.partition(".")
    if not sep or not expiry.isdigit():
        return False
    if not hmac.compare_digest(signature, _sign(settings.session_secret, expiry)):
        return False
    return int(expiry) > (now if now is not None else time.time())


def request_is_authenticated(request: Request, settings: Settings) -> bool:
    return verify_session_cookie(settings, request.cookies.get(COOKIE_NAME))


def require_session(request: Request, settings: Settings) -> None:
    if not request_is_authenticated(request, settings):
        raise HTTPException(status_code=401, detail="authentication required")


def client_ip(request: Request) -> str:
    # The backend only listens on loopback behind Caddy, which rewrites
    # X-Forwarded-For to the real client address, so the last entry is trustworthy.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"
