from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.auth import (
    COOKIE_NAME,
    client_ip,
    make_session_cookie,
    request_is_authenticated,
    verify_access_token,
)
from app.config import get_settings
from app.ratelimit import SlidingWindow

router = APIRouter(prefix="/api/auth", tags=["auth"])

_settings = get_settings()
verify_limiter = SlidingWindow(_settings.verify_rate_limit, _settings.verify_rate_window_seconds)


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1, max_length=512)


def _set_cookie(response: Response, value: str) -> None:
    settings = get_settings()
    response.set_cookie(
        COOKIE_NAME,
        value,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )


@router.post(
    "/verify",
    status_code=204,
    responses={
        401: {"description": "Invalid access token"},
        429: {"description": "Too many attempts; retry in a minute"},
        503: {"description": "Access gate is not configured"},
    },
)
def verify(body: VerifyRequest, request: Request, response: Response) -> Response:
    settings = get_settings()
    if not settings.auth_configured:
        raise HTTPException(status_code=503, detail="access gate is not configured")
    if not verify_limiter.allow(client_ip(request)):
        raise HTTPException(status_code=429, detail="too many attempts, try again in a minute")
    if not verify_access_token(settings, body.token):
        raise HTTPException(status_code=401, detail="invalid access token")
    response.status_code = 204
    _set_cookie(response, make_session_cookie(settings))
    return response


@router.post("/logout", status_code=204)
def logout(response: Response) -> Response:
    settings = get_settings()
    response.status_code = 204
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=settings.secure_cookies, samesite="lax")
    return response


class SessionStatus(BaseModel):
    authenticated: bool


@router.get("/session")
def session(request: Request) -> SessionStatus:
    return SessionStatus(authenticated=request_is_authenticated(request, get_settings()))
