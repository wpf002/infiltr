"""Postgres round-trip. Skipped unless INFILTR_TEST_PG_URL points at a live PG.

    INFILTR_TEST_PG_URL=postgresql+psycopg://user:pass@host:5432/db pytest tests/test_postgres.py
"""
import importlib
import os

import pytest

PG_URL = os.environ.get("INFILTR_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set INFILTR_TEST_PG_URL to run Postgres tests")


@pytest.fixture()
def store(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    import infiltr.db as db, infiltr.models as models, infiltr.store as store_mod
    importlib.reload(db); importlib.reload(models); importlib.reload(store_mod)
    db.init_db(force=True)
    # clean slate
    from sqlalchemy import text
    with db.engine.begin() as c:
        for t in ("findings", "module_results", "schedules", "profiles", "api_keys", "audit_log", "scan_runs", "users"):
            c.execute(text(f"DELETE FROM {t}"))
    return store_mod


def test_pg_scan_roundtrip_and_delta(store):
    from infiltr.base import ScanResult, Finding, PASS
    r = ScanResult(module="nmap", category="recon", target="http://x", status=PASS)
    r.findings = [Finding(type="open_port", name="80/tcp", value="http", severity="low"),
                  Finding(type="sqli", name="id", value="id", severity="critical")]
    r.compute_severity()
    sid = store.save_scan("http://x", [r], profile="full", duration=1.0)
    scan = store.get_scan(sid)
    assert scan["finding_count"] == 2 and scan["top_severity"] == "critical"
    assert store.apply_delta(sid)["new_count"] == 0  # first scan
    assert len(store.target_trend("http://x")) == 1


def test_pg_auth_and_profiles(store, monkeypatch):
    monkeypatch.setenv("INFILTR_SECRET_KEY", "test-secret-key-must-be-at-least-32-characters-long")
    import infiltr.auth.service as svc
    importlib.reload(svc)
    u = svc.create_user("a@x.com", "hunter2")
    assert u["role"] == "admin"
    assert svc.authenticate("a@x.com", "hunter2")
    p = store.create_profile("p1", ["nmap", "whatweb"], user_id=u["id"])
    assert set(store.get_profile(p["id"])["modules"]) == {"nmap", "whatweb"}
