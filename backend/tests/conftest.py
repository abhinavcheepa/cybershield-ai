"""Test fixtures.

The environment is configured before `app` is imported anywhere, because
`app.config.settings` is a cached singleton read at import time.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP_DB = Path(tempfile.gettempdir()) / "cybershield_test.db"
if _TMP_DB.exists():
    _TMP_DB.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ["SEED_DEMO_EVENTS"] = "40"
os.environ["JWT_SECRET"] = "test-secret-not-for-production"
os.environ["RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["ANTHROPIC_API_KEY"] = ""
# Pinned empty even if the developer's shell exports one: these tests cover the
# single-worker, in-process path, and should not depend on a running Redis.
# The shared path has its own check — `python -m app.detection.state`.
os.environ["REDIS_URL"] = ""
# The repo may hold a built frontend/dist; the API contract tests should not
# start answering `/` with an HTML shell depending on whether it does.
os.environ["SERVE_FRONTEND"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.seed import DEMO_PASSWORD  # noqa: E402


@pytest.fixture(scope="session")
def client():
    # The lifespan handler creates the schema and seeds it.
    with TestClient(app) as test_client:
        yield test_client


def _token(client: TestClient, email: str) -> str:
    response = client.post("/api/auth/login", json={"email": email, "password": DEMO_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture(scope="session")
def admin_headers(client) -> dict:
    return {"Authorization": f"Bearer {_token(client, 'admin@cybershield.io')}"}


@pytest.fixture(scope="session")
def analyst_headers(client) -> dict:
    return {"Authorization": f"Bearer {_token(client, 'analyst@cybershield.io')}"}


@pytest.fixture(scope="session")
def viewer_headers(client) -> dict:
    return {"Authorization": f"Bearer {_token(client, 'viewer@cybershield.io')}"}


@pytest.fixture(scope="session")
def viewer_token(client) -> str:
    return _token(client, "viewer@cybershield.io")
