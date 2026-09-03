import time

from app.auth import COOKIE_NAME, make_session_cookie, verify_session_cookie
from app.config import Settings


def _settings(**kw):
    base = dict(access_token="t", session_secret="s", anthropic_api_key=None, secure_cookies=False)
    base.update(kw)
    return Settings(**base)


def test_session_cookie_roundtrip():
    s = _settings()
    cookie = make_session_cookie(s, now=1000.0)
    assert verify_session_cookie(s, cookie, now=1000.0 + s.session_ttl_seconds - 1)
    assert not verify_session_cookie(s, cookie, now=1000.0 + s.session_ttl_seconds + 1)


def test_session_cookie_rejects_tampering_and_other_secret():
    s = _settings()
    cookie = make_session_cookie(s)
    expiry, sig = cookie.split(".")
    assert not verify_session_cookie(s, f"{int(expiry) + 99999}.{sig}")
    assert not verify_session_cookie(_settings(session_secret="other"), cookie)
    assert not verify_session_cookie(s, "garbage")
    assert not verify_session_cookie(s, None)


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["attack_dataset_version"] == "19.2"
    assert body["attack_technique_count"] == 697


def test_verify_sets_cookie_and_session_reports_it(client):
    assert client.get("/api/auth/session").json() == {"authenticated": False}
    r = client.post("/api/auth/verify", json={"token": "test-access-token"})
    assert r.status_code == 204
    assert COOKIE_NAME in r.cookies
    assert client.get("/api/auth/session").json() == {"authenticated": True}
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/session").json() == {"authenticated": False}


def test_wrong_token_rejected(client):
    r = client.post("/api/auth/verify", json={"token": "nope"})
    assert r.status_code == 401
    assert COOKIE_NAME not in r.cookies


def test_verify_rate_limited_per_ip(client):
    for _ in range(10):
        assert client.post("/api/auth/verify", json={"token": "nope"}).status_code == 401
    assert client.post("/api/auth/verify", json={"token": "nope"}).status_code == 429
    # A different client IP is unaffected.
    r = client.post("/api/auth/verify", json={"token": "nope"}, headers={"x-forwarded-for": "203.0.113.9"})
    assert r.status_code == 401


def test_protected_routes_need_cookie(client):
    assert client.get("/api/does-not-exist").status_code == 401


def test_oversize_body_rejected_before_parsing(authed_client):
    r = authed_client.post("/api/auth/verify", content="x" * (64 * 1024 + 1), headers={"content-type": "application/json"})
    assert r.status_code == 413
