"""Prometheus /metrics endpoint + counters."""
import pytest

pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from infiltr.api.app import app  # noqa: E402
from infiltr.api import metrics  # noqa: E402


def test_render_contains_core_series():
    metrics.record_scan_started()
    metrics.record_scan_finished("completed", 12.0)
    out = metrics.render()
    assert "infiltr_up 1" in out
    assert "infiltr_scans_started_total" in out
    assert 'infiltr_scans_finished_total{status="completed"}' in out
    assert "infiltr_modules_registered" in out


def test_metrics_endpoint_text():
    c = TestClient(app)
    r = c.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "infiltr_up 1" in r.text


def test_metrics_token_gating(monkeypatch):
    monkeypatch.setattr(metrics, "METRICS_TOKEN", "sekret")
    c = TestClient(app)
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"X-Metrics-Token": "sekret"}).status_code == 200
    assert c.get("/metrics", headers={"Authorization": "Bearer sekret"}).status_code == 200


def test_metrics_can_be_disabled(monkeypatch):
    monkeypatch.setattr(metrics, "METRICS_ENABLED", False)
    c = TestClient(app)
    assert c.get("/metrics").status_code == 404
