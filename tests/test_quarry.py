"""Quarry delegation API: auth, tier enforcement, single-target, response schema."""
import os
import socket
import subprocess
import sys
import time

import pytest

httpx = pytest.importorskip("httpx")
pytest.importorskip("uvicorn")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def qserver(tmp_path):
    port = _free_port()
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{tmp_path/'q.db'}", PYTHONPATH=ROOT,
               INFILTR_AUTH="1", INFILTR_SECRET_KEY="test-secret-key-must-be-at-least-32-characters-long", INFILTR_ALLOW_NO_ALLOWLIST="1")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "infiltr.api.app:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    else:
        proc.terminate(); pytest.fail("server did not start")
    # bootstrap admin + API key
    admin = httpx.post(f"{base}/auth/register",
                       json={"email": "q@x.com", "password": "pw123456", "accepted_tos": True}).json()
    key = httpx.post(f"{base}/auth/api-keys", headers={"Authorization": f"Bearer {admin['access_token']}"},
                     json={"name": "quarry"}).json()["api_key"]
    yield base, key
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _bearer(key):
    return {"Authorization": f"Bearer {key}"}


def test_requires_bearer(qserver):
    base, _ = qserver
    assert httpx.post(f"{base}/v1/quarry/scan", json={"target": "localhost"}).status_code == 401
    assert httpx.post(f"{base}/v1/quarry/scan", headers={"Authorization": "Bearer nope"},
                      json={"target": "localhost"}).status_code == 401


def test_tier3_refused(qserver):
    base, key = qserver
    r = httpx.post(f"{base}/v1/quarry/scan", headers=_bearer(key),
                   json={"target": "localhost", "profile": {"tiers": [3]}})
    assert r.status_code == 400


def test_single_target_enforced(qserver):
    base, key = qserver
    r = httpx.post(f"{base}/v1/quarry/scan", headers=_bearer(key),
                   json={"target": "a.com, b.com", "profile": {"tiers": [1]}})
    assert r.status_code == 400


def test_sync_scan_schema(qserver):
    base, key = qserver
    # tier-1 with a tool allowlist keeps it fast; tools missing on host -> skip_missing
    r = httpx.post(f"{base}/v1/quarry/scan", headers=_bearer(key),
                   json={"target": "http://localhost:8080", "profile": {"tiers": [1], "tools": ["httpx"]}},
                   timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    # schema must be exactly these three keys
    assert set(body.keys()) == {"target", "assets", "findings"}
    assert body["target"] == "http://localhost:8080"
    assert isinstance(body["assets"], list)
    for f in body["findings"]:
        assert set(f.keys()) >= {"title", "vulnClass", "severity", "evidence"}
        assert f["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_async_start_and_poll(qserver):
    base, key = qserver
    start = httpx.post(f"{base}/v1/quarry/scan?wait=false", headers=_bearer(key),
                       json={"target": "http://localhost:8080", "profile": {"tiers": [1], "tools": ["httpx"]}})
    assert start.status_code == 200
    job_id = start.json()["job_id"]
    assert start.json()["status"] == "running"
    for _ in range(120):
        poll = httpx.get(f"{base}/v1/quarry/scan/{job_id}", headers=_bearer(key)).json()
        if poll["status"] in ("completed", "interrupted", "error", "cancelled"):
            break
        time.sleep(0.25)
    assert poll["status"] == "completed"
    assert poll["target"] == "http://localhost:8080"
    assert isinstance(poll["findings"], list)


def test_job_scoped_to_owner(qserver):
    base, key = qserver
    job_id = httpx.post(f"{base}/v1/quarry/scan?wait=false", headers=_bearer(key),
                        json={"target": "http://localhost:8080", "profile": {"tiers": [1], "tools": ["httpx"]}}).json()["job_id"]
    # a different user's key can't read it
    other = httpx.post(f"{base}/auth/register",
                       json={"email": "o@x.com", "password": "pw123456", "accepted_tos": True}).json()
    okey = httpx.post(f"{base}/auth/api-keys", headers={"Authorization": f"Bearer {other['access_token']}"},
                      json={"name": "o"}).json()["api_key"]
    assert httpx.get(f"{base}/v1/quarry/scan/{job_id}", headers=_bearer(okey)).status_code == 404
