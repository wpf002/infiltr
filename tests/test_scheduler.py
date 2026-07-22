"""Cron matching, delta detection, trend, and schedule persistence."""
from datetime import datetime

import pytest

from infiltr.scheduler.cron import cron_matches, validate_cron
from infiltr.base import ScanResult, Finding, PASS


# ---- cron -------------------------------------------------------------
def test_validate_cron():
    assert validate_cron("0 * * * *")
    assert validate_cron("*/15 9-17 * * 1-5")
    assert not validate_cron("nonsense")
    assert not validate_cron("* * * *")  # only 4 fields


@pytest.mark.parametrize("expr,when,expected", [
    ("0 * * * *", datetime(2026, 7, 21, 14, 0), True),
    ("0 * * * *", datetime(2026, 7, 21, 14, 30), False),
    ("*/15 * * * *", datetime(2026, 7, 21, 14, 30), True),
    ("*/15 * * * *", datetime(2026, 7, 21, 14, 31), False),
    ("30 9 * * *", datetime(2026, 7, 21, 9, 30), True),
    ("0 0 1 * *", datetime(2026, 7, 1, 0, 0), True),
    ("0 0 1 * *", datetime(2026, 7, 2, 0, 0), False),
    # 2026-07-20 is a Monday -> cron dow 1
    ("0 12 * * 1", datetime(2026, 7, 20, 12, 0), True),
    ("0 12 * * 2", datetime(2026, 7, 20, 12, 0), False),
])
def test_cron_matches(expr, when, expected):
    assert cron_matches(expr, when) is expected


# ---- delta / trend / schedules (isolated db) --------------------------
@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'sched.db'}")
    import importlib
    import infiltr.db as db, infiltr.models as models, infiltr.store as store_mod
    importlib.reload(db); importlib.reload(models); importlib.reload(store_mod)
    return store_mod


def _result(module, findings):
    r = ScanResult(module=module, category="web", target="http://t", status=PASS)
    r.findings = findings
    r.compute_severity()
    return r


def test_delta_detection(store):
    # scan 1: two findings
    s1 = store.save_scan("http://t", [_result("nmap", [
        Finding(type="open_port", name="80/tcp", value="http", severity="low"),
        Finding(type="open_port", name="22/tcp", value="ssh", severity="low"),
    ])], duration=1.0)
    store.apply_delta(s1)  # first scan -> nothing new

    # scan 2: 22/tcp gone, 3306 appears
    s2 = store.save_scan("http://t", [_result("nmap", [
        Finding(type="open_port", name="80/tcp", value="http", severity="low"),
        Finding(type="open_port", name="3306/tcp", value="mysql", severity="medium"),
    ])], duration=1.0)
    summary = store.apply_delta(s2)
    assert summary["new_count"] == 1
    assert summary["previous_scan_id"] == s1

    delta = store.scan_delta(s2)
    assert any(f["name"] == "3306/tcp" for f in delta["new"])
    assert any(f["name"] == "22/tcp" for f in delta["resolved"])


def test_first_scan_has_no_new(store):
    sid = store.save_scan("http://t", [_result("nmap", [
        Finding(type="open_port", name="80/tcp", value="http", severity="low"),
    ])], duration=1.0)
    assert store.apply_delta(sid)["new_count"] == 0


def test_target_trend(store):
    for _ in range(3):
        store.save_scan("http://t", [_result("nmap", [
            Finding(type="open_port", name="80/tcp", value="http", severity="low"),
        ])], duration=1.0)
    trend = store.target_trend("http://t")
    assert len(trend) == 3
    assert trend[0]["scan_id"] < trend[-1]["scan_id"]  # chronological


def test_schedule_crud(store):
    sc = store.create_schedule("http://t", "*/30 * * * *", name="nightly", profile="quick",
                               alerts={"webhook": "http://hook"})
    sid = sc["id"]
    assert store.get_schedule(sid)["cron"] == "*/30 * * * *"
    assert len(store.list_schedules()) == 1
    assert store.list_schedules(only_enabled=True)

    store.update_schedule(sid, enabled=False)
    assert store.list_schedules(only_enabled=True) == []

    store.mark_schedule_run(sid, 123)
    assert store.get_schedule(sid)["last_scan_id"] == 123

    assert store.delete_schedule(sid) is True
    assert store.get_schedule(sid) is None
