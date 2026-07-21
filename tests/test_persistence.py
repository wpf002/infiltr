"""Persistence round-trip: save ScanResults, query them back."""
import os

import pytest

from infiltr.base import ScanResult, Finding, PASS


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    # reload db + store so they pick up the env var
    import importlib
    import infiltr.db as db
    import infiltr.models as models
    import infiltr.store as store
    importlib.reload(db)
    importlib.reload(models)
    importlib.reload(store)
    return store


def _sample_results():
    r1 = ScanResult(module="nmap", category="recon", target="http://localhost:8080", status=PASS)
    r1.findings = [
        Finding(type="open_port", name="80/tcp", value="http", severity="low"),
        Finding(type="open_port", name="3306/tcp", value="mysql", severity="medium"),
    ]
    r1.compute_severity()
    r2 = ScanResult(module="sqlmap", category="web", target="http://localhost:8080", status=PASS)
    r2.findings = [Finding(type="sqli", name="id", value="id", severity="critical")]
    r2.compute_severity()
    return [r1, r2]


def test_save_and_get(tmp_db):
    store = tmp_db
    scan_id = store.save_scan("http://localhost:8080", _sample_results(), profile="full", duration=12.3)
    assert scan_id >= 1

    scan = store.get_scan(scan_id)
    assert scan["target"] == "http://localhost:8080"
    assert scan["finding_count"] == 3
    assert scan["top_severity"] == "critical"
    assert len(scan["results"]) == 2
    assert scan["results"][0]["findings"]


def test_history_and_histogram(tmp_db):
    store = tmp_db
    sid = store.save_scan("http://a", _sample_results(), duration=1.0)
    store.save_scan("http://b", _sample_results(), duration=1.0)
    hist = store.list_scans(limit=10)
    assert len(hist) == 2
    assert hist[0]["id"] > hist[1]["id"]  # newest first

    histogram = store.severity_histogram(sid)
    assert histogram["critical"] == 1
    assert histogram["medium"] == 1
    assert histogram["low"] == 1


def test_delete(tmp_db):
    store = tmp_db
    sid = store.save_scan("http://a", _sample_results(), duration=1.0)
    assert store.delete_scan(sid) is True
    assert store.get_scan(sid) is None
    assert store.delete_scan(sid) is False
