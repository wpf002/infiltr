"""Cross-node shared state: concurrency reservations + sliding-window rate limits.

Local (in-process) mode always runs. The Redis path runs only when
INFILTR_TEST_REDIS_URL is set (e.g. redis://127.0.0.1:6399/0)."""
import os
import importlib

import pytest


def _fresh(redis_url=None):
    """Reload shared_state so module-level REDIS_URL is re-read from the env."""
    if redis_url is None:
        os.environ.pop("REDIS_URL", None)
    else:
        os.environ["REDIS_URL"] = redis_url
    import infiltr.shared_state as s
    importlib.reload(s)
    s.reset_local()
    return s


# ---- local (in-process) mode ------------------------------------------
def test_local_disabled_by_default():
    s = _fresh()
    assert s.enabled() is False


def test_local_global_cap():
    s = _fresh()
    a, _ = s.reserve("a", 5, 2)
    b, _ = s.reserve("b", 5, 2)
    c, reason = s.reserve("c", 5, 2)
    assert a and b and c is None
    assert "capacity" in reason


def test_local_user_cap_and_release():
    s = _fresh()
    r1, _ = s.reserve("u", 2, 10)
    r2, _ = s.reserve("u", 2, 10)
    r3, reason = s.reserve("u", 2, 10)
    assert r1 and r2 and r3 is None and "max 2" in reason
    s.release(r1)
    r4, _ = s.reserve("u", 2, 10)
    assert r4 is not None


def test_local_rate_limit_sliding_window():
    s = _fresh()
    assert [s.allow_request("k", 3, 60) for _ in range(4)] == [True, True, True, False]
    # a different bucket is independent
    assert s.allow_request("other", 3, 60) is True


def test_release_none_is_noop():
    s = _fresh()
    s.release(None)  # must not raise


# ---- redis mode (opt-in) ----------------------------------------------
REDIS_URL = os.environ.get("INFILTR_TEST_REDIS_URL")


@pytest.mark.skipif(not REDIS_URL, reason="set INFILTR_TEST_REDIS_URL to run Redis tests")
def test_redis_enabled_and_caps():
    s = _fresh(REDIS_URL)
    try:
        c = s._client()
        assert c is not None
        c.flushall()
        assert s.enabled() is True
        a, _ = s.reserve("a", 2, 3)
        b, _ = s.reserve("b", 2, 3)
        cc, _ = s.reserve("c", 2, 3)
        d, reason = s.reserve("d", 2, 3)
        assert a and b and cc and d is None and "capacity" in reason
        s.release(a)
        d2, _ = s.reserve("d", 2, 3)
        assert d2 is not None
        assert c.zcard(s._gkey()) == 3
    finally:
        _fresh()  # restore local mode for the rest of the suite


@pytest.mark.skipif(not REDIS_URL, reason="set INFILTR_TEST_REDIS_URL to run Redis tests")
def test_redis_rate_limit():
    s = _fresh(REDIS_URL)
    try:
        s._client().flushall()
        assert [s.allow_request("ip", 3, 60) for _ in range(4)] == [True, True, True, False]
    finally:
        _fresh()
