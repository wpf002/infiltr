"""Lightweight Prometheus metrics (text exposition format, no dependency).

Process-local counters plus a live snapshot of manager/store/shared_state state.
With multiple replicas each exposes its own counters; scrape them per-instance
and aggregate in Prometheus (standard for a horizontally-scaled service). Gauges
that must be global (running scans, capacity) are read from Redis-backed shared
state where available, so they're consistent across replicas.
"""
from __future__ import annotations

import os
import threading
import time

_lock = threading.Lock()
_START = time.monotonic()

# counters (monotonic, process-local)
_scans_started = 0
_scans_finished: dict[str, int] = {}          # status -> count
_scan_duration_sum = 0.0
_rate_limited = 0

METRICS_ENABLED = os.environ.get("INFILTR_METRICS", "1") in ("1", "true", "True")
METRICS_TOKEN = os.environ.get("INFILTR_METRICS_TOKEN", "").strip()


def record_scan_started() -> None:
    global _scans_started
    with _lock:
        _scans_started += 1


def record_scan_finished(status: str, duration_s: float) -> None:
    global _scan_duration_sum
    with _lock:
        _scans_finished[status] = _scans_finished.get(status, 0) + 1
        _scan_duration_sum += max(0.0, duration_s)


def record_rate_limited() -> None:
    global _rate_limited
    with _lock:
        _rate_limited += 1


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


def render() -> str:
    """Return the metrics exposition. Aggregates only — no per-user data."""
    from .manager import manager, GLOBAL_MAX
    from .. import shared_state
    from ..engine import discover, invalid_modules

    with _lock:
        started = _scans_started
        finished = dict(_scans_finished)
        dur_sum = _scan_duration_sum
        limited = _rate_limited

    running = sum(1 for j in manager.jobs.values() if j.status == "running")
    finished_total = sum(finished.values())
    try:
        registry = discover()
        modules_registered = len(registry)
        modules_installed = sum(1 for m in registry.values() if m.is_installed())
    except Exception:  # noqa: BLE001
        modules_registered = modules_installed = 0
    try:
        modules_invalid = len(invalid_modules())
    except Exception:  # noqa: BLE001
        modules_invalid = 0

    lines: list[str] = []

    def g(name: str, value, help_: str, typ: str = "gauge", labels: str = ""):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {typ}")
        lines.append(f"{name}{('{' + labels + '}') if labels else ''} {value}")

    g("infiltr_up", 1, "1 if the API is serving.")
    g("infiltr_uptime_seconds", round(time.monotonic() - _START, 1), "Seconds since process start.", "counter")
    g("infiltr_scans_started_total", started, "Scans accepted and started.", "counter")
    g("infiltr_scan_duration_seconds_sum", round(dur_sum, 2),
      "Cumulative scan wall-clock; divide by finished total for the mean.", "counter")
    g("infiltr_rate_limited_total", limited, "Requests rejected by a rate limiter.", "counter")
    g("infiltr_scans_running", running, "Scans currently running on this replica.")
    g("infiltr_scan_capacity", GLOBAL_MAX, "Configured global concurrent-scan cap.")
    g("infiltr_redis_enabled", 1 if shared_state.enabled() else 0, "1 if Redis-backed shared state is active.")
    g("infiltr_modules_registered", modules_registered, "Discovered scan modules.")
    g("infiltr_modules_installed", modules_installed, "Modules whose tool is installed.")
    g("infiltr_modules_invalid", modules_invalid, "Modules that failed validation.")

    # per-status finished counter (one series per status label)
    lines.append("# HELP infiltr_scans_finished_total Scans finished, by terminal status.")
    lines.append("# TYPE infiltr_scans_finished_total counter")
    if finished:
        for status, n in sorted(finished.items()):
            lines.append(f'infiltr_scans_finished_total{{status="{_esc(status)}"}} {n}')
    else:
        lines.append('infiltr_scans_finished_total{status="none"} 0')
    _ = finished_total  # (kept for readability; sum available via the series)

    return "\n".join(lines) + "\n"
