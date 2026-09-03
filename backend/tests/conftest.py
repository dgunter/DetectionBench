import os

import pytest

os.environ.setdefault("DETECTIONBENCH_ACCESS_TOKEN", "test-access-token")
os.environ.setdefault("DETECTIONBENCH_SESSION_SECRET", "test-session-secret")
os.environ.setdefault("DETECTIONBENCH_INSECURE_COOKIES", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app.api.auth import verify_limiter  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def client():
    verify_limiter.reset()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def authed_client(client):
    r = client.post("/api/auth/verify", json={"token": "test-access-token"})
    assert r.status_code == 204
    return client
