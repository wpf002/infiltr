"""Scan cancellation: engine skips queued modules and kills running processes."""
import threading
import time

from infiltr.base import BaseWrapper, Finding, ERROR
from infiltr import engine


def test_engine_cancel_before_run_skips_all():
    eng = engine.Engine(modules=["nmap", "whatweb"])
    eng.cancel()
    results = eng.run("http://localhost:8080")
    assert results, "expected results even when cancelled"
    assert all(r.status == ERROR and r.error == "cancelled" for r in results)


class _SleepWrapper(BaseWrapper):
    MODULE_NAME = "sleeper"
    CATEGORY = "misc"
    TOOL_BIN = "sleep"

    def build_command(self, target):
        return ["sleep", "30"]

    def parse_output(self, stdout, stderr, rc):
        return [Finding(type="x", name="y")]


def test_terminate_kills_running_process():
    w = _SleepWrapper(options={"timeout": 60})
    result = {}

    def go():
        result["res"] = w.run("x")

    t = threading.Thread(target=go)
    t.start()
    time.sleep(0.5)          # let the process start
    w.terminate()            # kill it
    t.join(timeout=5)
    assert not t.is_alive(), "wrapper did not stop after terminate()"
    assert result["res"].status == ERROR
    assert result["res"].error == "cancelled"
    assert result["res"].duration < 5    # stopped quickly, not the 30s sleep
