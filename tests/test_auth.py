"""Auth + multi-tenancy: security primitives (unit) and full flow (live server)."""
import os
import socket
import subprocess
import sys
import time

import pytest

httpx = pytest.importorskip("httpx")
pytest.importorskip("uvicorn")

from infiltr.auth import security  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- unit: security ---------------------------------------------------
def test_password_hash_roundtrip():
    h = security.hash_password("s3cret!")
    assert h != "s3cret!"
    assert security.verify_password("s3cret!", h)
    assert not security.verify_password("wrong", h)


def test_jwt_roundtrip_and_tamper():
    tok = security.create_token(42, "admin", "access")
    payload = security.decode_token(tok)
    assert payload["sub"] == 42 and payload["role"] == "admin" and payload["type"] == "access"
    assert security.decode_token(tok + "x") is None  # tampered signature


def test_jwt_expiry():
    tok = security.create_token(1, "viewer", "access", ttl=-1)
    assert security.decode_token(tok) is None


def test_api_key_generation():
    full, prefix, key_hash = security.generate_api_key()
    assert full.startswith(prefix)
    assert security.hash_api_key(full) == key_hash


# ---- integration: auth-enabled server ---------------------------------
def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def auth_server(tmp_path):
    port = _free_port()
    env = dict(
        os.environ,
        DATABASE_URL=f"sqlite:///{tmp_path/'auth.db'}",
        PYTHONPATH=ROOT,
        INFILTR_AUTH="1",
        INFILTR_SECRET_KEY="test-secret-key",
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "infiltr.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    else:
        proc.terminate(); pytest.fail("auth server did not start")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_auth_required_when_enabled(auth_server):
    assert httpx.get(f"{auth_server}/scans").status_code == 401


def test_register_login_me_and_first_is_admin(auth_server):
    reg = httpx.post(f"{auth_server}/auth/register", json={"email": "a@x.com", "password": "hunter2"})
    assert reg.status_code == 200, reg.text
    data = reg.json()
    assert data["user"]["role"] == "admin"  # first user bootstraps as admin
    tok = data["access_token"]
    me = httpx.get(f"{auth_server}/auth/me", headers=_auth(tok)).json()
    assert me["email"] == "a@x.com"

    login = httpx.post(f"{auth_server}/auth/login", json={"email": "a@x.com", "password": "hunter2"})
    assert login.status_code == 200
    assert httpx.post(f"{auth_server}/auth/login", json={"email": "a@x.com", "password": "bad"}).status_code == 401


def test_scans_scoped_per_user(auth_server):
    admin = httpx.post(f"{auth_server}/auth/register", json={"email": "admin@x.com", "password": "pw123456"}).json()
    op = httpx.post(f"{auth_server}/auth/register", json={"email": "op@x.com", "password": "pw123456"}).json()

    sid = httpx.post(f"{auth_server}/scan", headers=_auth(admin["access_token"]),
                     json={"target": "http://localhost:8080", "modules": ["nmap"]}).json()["scan_id"]
    # owner sees it
    assert httpx.get(f"{auth_server}/scan/{sid}", headers=_auth(admin["access_token"])).status_code == 200
    # other user does not
    assert httpx.get(f"{auth_server}/scan/{sid}", headers=_auth(op["access_token"])).status_code == 404
    assert httpx.get(f"{auth_server}/scans", headers=_auth(op["access_token"])).json() == []


def test_rbac_admin_only(auth_server):
    httpx.post(f"{auth_server}/auth/register", json={"email": "admin@x.com", "password": "pw123456"})  # admin
    op = httpx.post(f"{auth_server}/auth/register", json={"email": "op@x.com", "password": "pw123456"}).json()
    assert op["user"]["role"] == "operator"
    # operator cannot list users
    assert httpx.get(f"{auth_server}/admin/users", headers=_auth(op["access_token"])).status_code == 403


def test_api_key_auth_and_audit(auth_server):
    admin = httpx.post(f"{auth_server}/auth/register", json={"email": "admin@x.com", "password": "pw123456"}).json()
    tok = admin["access_token"]
    key = httpx.post(f"{auth_server}/auth/api-keys", headers=_auth(tok), json={"name": "ci"}).json()
    assert "api_key" in key
    # use the API key to authenticate a scan
    r = httpx.post(f"{auth_server}/scan", headers={"X-API-Key": key["api_key"]},
                   json={"target": "http://localhost:8080", "modules": ["nmap"]})
    assert r.status_code == 200
    # audit log records events (admin only)
    audit = httpx.get(f"{auth_server}/admin/audit", headers=_auth(tok)).json()
    actions = {a["action"] for a in audit}
    assert "user.register" in actions and "scan.start" in actions


def test_refresh_rotation(auth_server):
    reg = httpx.post(f"{auth_server}/auth/register", json={"email": "a@x.com", "password": "pw123456"}).json()
    new = httpx.post(f"{auth_server}/auth/refresh", json={"refresh_token": reg["refresh_token"]})
    assert new.status_code == 200 and "access_token" in new.json()
    # an access token is not a valid refresh token
    assert httpx.post(f"{auth_server}/auth/refresh", json={"refresh_token": reg["access_token"]}).status_code == 401
