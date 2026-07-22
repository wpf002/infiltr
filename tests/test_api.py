"""API tests against a live uvicorn server (faithful to background tasks + SSE).

TestClient can't pump the fire-and-forget scan task between requests, so we run
the real server on a random port with an isolated temp DB.
"""
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
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def server(tmp_path):
    port = _free_port()
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{tmp_path/'api.db'}", PYTHONPATH=ROOT)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "infiltr.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    # wait for readiness
    for _ in range(100):
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("server did not start")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_health(server):
    assert httpx.get(f"{server}/health").json()["status"] == "ok"


def test_modules(server):
    names = {m["name"] for m in httpx.get(f"{server}/modules").json()}
    assert {"nmap", "sqlmap", "hydra"}.issubset(names)


def test_scan_lifecycle(server):
    r = httpx.post(f"{server}/scan", json={"target": "http://localhost:8080", "modules": ["nmap", "whatweb"]})
    assert r.status_code == 200, r.text
    scan_id = r.json()["scan_id"]

    for _ in range(100):
        scan = httpx.get(f"{server}/scan/{scan_id}").json()
        if scan["status"] == "completed":
            break
        time.sleep(0.1)
    assert scan["status"] == "completed"
    assert scan["module_count"] == 2

    assert any(s["id"] == scan_id for s in httpx.get(f"{server}/scans").json())
    assert httpx.delete(f"{server}/scan/{scan_id}").status_code == 200
    assert httpx.get(f"{server}/scan/{scan_id}").status_code == 404


def test_scan_events_stream(server):
    scan_id = httpx.post(f"{server}/scan", json={"target": "http://localhost:8080", "modules": ["nmap"]}).json()["scan_id"]
    saw_done = False
    with httpx.stream("GET", f"{server}/scan/{scan_id}/events", timeout=15) as resp:
        assert resp.status_code == 200
        for line in resp.iter_lines():
            if "done" in line:
                saw_done = True
                break
    assert saw_done


def test_profiles_resolution(server):
    # 'quick' profile resolves to nmap + whatweb server-side
    scan_id = httpx.post(f"{server}/scan", json={"target": "http://localhost:8080", "profile": "quick"}).json()["scan_id"]
    for _ in range(100):
        scan = httpx.get(f"{server}/scan/{scan_id}").json()
        if scan["status"] == "completed":
            break
        time.sleep(0.1)
    assert {r["module"] for r in scan["results"]} == {"nmap", "whatweb"}


def test_profiles_crud(server):
    # built-ins are present
    profs = httpx.get(f"{server}/profiles").json()
    names = {p["name"] for p in profs}
    assert {"full", "quick", "web-audit", "auth-test"}.issubset(names)

    # create
    created = httpx.post(f"{server}/profiles", json={
        "name": "recon-lite", "modules": ["nmap"], "description": "just nmap",
    }).json()
    pid = created["id"]
    assert pid is not None

    # appears in list
    assert any(p.get("id") == pid for p in httpx.get(f"{server}/profiles").json())

    # update
    upd = httpx.put(f"{server}/profiles/{pid}", json={
        "name": "recon-lite", "modules": ["nmap", "whatweb"], "description": "nmap+whatweb",
    }).json()
    assert set(upd["modules"]) == {"nmap", "whatweb"}

    # a scan using the profile resolves to its modules
    scan_id = httpx.post(f"{server}/scan", json={"target": "http://localhost:8080", "profile": "recon-lite"}).json()["scan_id"]
    for _ in range(100):
        scan = httpx.get(f"{server}/scan/{scan_id}").json()
        if scan["status"] == "completed":
            break
        time.sleep(0.1)
    assert {r["module"] for r in scan["results"]} == {"nmap", "whatweb"}

    # delete
    assert httpx.delete(f"{server}/profiles/{pid}").status_code == 200
    assert httpx.delete(f"{server}/profiles/{pid}").status_code == 404


def test_schedule_crud_and_run_now(server):
    # invalid cron rejected
    assert httpx.post(f"{server}/schedules", json={"target": "http://localhost:8080", "cron": "bad"}).status_code == 400

    created = httpx.post(f"{server}/schedules", json={
        "target": "http://localhost:8080", "cron": "*/30 * * * *", "name": "nightly", "profile": "quick",
    }).json()
    sid = created["id"]
    assert any(s["id"] == sid for s in httpx.get(f"{server}/schedules").json())

    # run now -> triggers a scan using the profile
    run = httpx.post(f"{server}/schedules/{sid}/run").json()
    scan_id = run["scan_id"]
    for _ in range(100):
        scan = httpx.get(f"{server}/scan/{scan_id}").json()
        if scan["status"] == "completed":
            break
        time.sleep(0.1)
    assert {r["module"] for r in scan["results"]} == {"nmap", "whatweb"}

    # delta + trend endpoints respond
    assert "new" in httpx.get(f"{server}/scan/{scan_id}/delta").json()
    trend = httpx.get(f"{server}/targets/trend", params={"target": "http://localhost:8080"}).json()
    assert isinstance(trend, list) and trend

    assert httpx.delete(f"{server}/schedules/{sid}").status_code == 200


def test_scope_rejection(server):
    # blocklisted cloud metadata endpoint is refused
    r = httpx.post(f"{server}/scan", json={"target": "http://169.254.169.254/", "modules": ["nmap"]})
    assert r.status_code == 403
    # argument-injection target refused
    r2 = httpx.post(f"{server}/scan", json={"target": "-oG/tmp/x", "modules": ["nmap"]})
    assert r2.status_code == 403


def test_unknown_scan_404(server):
    assert httpx.get(f"{server}/scan/99999").status_code == 404
