"""Cross-node shared state: concurrency reservations + rate limiting.

Single-node/dev keeps the original in-process counters (no dependency). When
``REDIS_URL`` is set the same operations run in Redis so N API replicas share one
global cap and one rate-limit window.

Design notes:
- Concurrency slots are members of a Redis sorted set scored by reservation time.
  Counting evicts entries older than ``INFILTR_SCAN_MAX_AGE`` first, so a replica
  that crashes mid-scan can't leak a slot forever (the stale member ages out).
  Reserve is a single Lua script → atomic check-and-add across the global and
  per-user sets, so two replicas can't both pass the cap.
- Rate limiting is a sliding-window sorted set (one op via Lua).
- Any Redis error degrades to the in-process path for that call rather than
  failing the request; concurrency then falls back to a local counter and rate
  limiting fails open (logs, allows) to avoid locking users out on an outage.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from .api.logging_setup import get_logger

log = get_logger("infiltr.shared_state")

REDIS_URL = os.environ.get("REDIS_URL", "").strip()
SCAN_MAX_AGE = int(os.environ.get("INFILTR_SCAN_MAX_AGE", "3600"))  # slot-leak guard
_KEY_PREFIX = os.environ.get("INFILTR_REDIS_PREFIX", "infiltr")

# ---- redis client (lazy, optional) ------------------------------------
_redis = None
_redis_init = False
_redis_lock = threading.Lock()


def _client():
    """Return a connected redis client, or None if unavailable/unconfigured."""
    global _redis, _redis_init
    if _redis_init:
        return _redis
    with _redis_lock:
        if _redis_init:
            return _redis
        _redis_init = True
        if not REDIS_URL:
            return None
        try:
            import redis  # type: ignore
            c = redis.Redis.from_url(
                REDIS_URL, socket_timeout=1.5, socket_connect_timeout=1.5,
                decode_responses=True,
            )
            c.ping()
            _redis = c
            log.info("shared_state_redis_connected", extra={"url": _redacted(REDIS_URL)})
        except Exception as exc:  # noqa: BLE001 - any failure => in-process fallback
            log.warning("shared_state_redis_unavailable",
                        extra={"error": str(exc)[:200], "url": _redacted(REDIS_URL)})
            _redis = None
        return _redis


def _redacted(url: str) -> str:
    # hide credentials in redis://user:pass@host
    if "@" in url:
        return url.split("@", 1)[0].split("//", 1)[0] + "//***@" + url.split("@", 1)[1]
    return url


def enabled() -> bool:
    """True when a Redis backend is active (multi-node mode)."""
    return _client() is not None


# ---- concurrency reservations -----------------------------------------
_local_active: dict[str, int] = defaultdict(int)
_local_global = 0
_local_lock = threading.Lock()

# KEYS[1]=global set, KEYS[2]=user set
# ARGV: 1=global_cap 2=user_cap 3=now 4=min_score(now-maxage) 5=member
_RESERVE_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[4])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return -1 end
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[5])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[5])
return 1
"""


class Reservation:
    """Opaque handle returned by reserve(); pass to release()."""
    __slots__ = ("key", "token", "redis")

    def __init__(self, key: str, token: str, redis: bool) -> None:
        self.key = key
        self.token = token
        self.redis = redis


def reserve(key: str, user_cap: int, global_cap: int) -> tuple[Optional[Reservation], str]:
    """Atomically reserve one global + one per-user slot.

    Returns (Reservation, "") on success, or (None, reason) if a cap is hit.
    """
    c = _client()
    if c is not None:
        try:
            now = time.time()
            token = secrets.token_hex(8)
            rc = c.eval(_RESERVE_LUA, 2, _gkey(), _ukey(key),
                        global_cap, user_cap, now, now - SCAN_MAX_AGE, token)
            rc = int(rc)
            if rc == 1:
                return Reservation(key, token, True), ""
            if rc == 0:
                return None, f"server at capacity ({global_cap} concurrent scans)"
            return None, f"max {user_cap} concurrent scans reached"
        except Exception as exc:  # noqa: BLE001 - fall back to local counter
            log.warning("reserve_redis_failed", extra={"error": str(exc)[:200]})
    # in-process fallback
    global _local_global
    with _local_lock:
        if _local_global >= global_cap:
            return None, f"server at capacity ({global_cap} concurrent scans)"
        if _local_active[key] >= user_cap:
            return None, f"max {user_cap} concurrent scans reached"
        _local_active[key] += 1
        _local_global += 1
    return Reservation(key, "", False), ""


def release(res: Optional[Reservation]) -> None:
    if res is None:
        return
    if res.redis:
        c = _client()
        if c is not None:
            try:
                c.zrem(_gkey(), res.token)
                c.zrem(_ukey(res.key), res.token)
                return
            except Exception as exc:  # noqa: BLE001
                log.warning("release_redis_failed", extra={"error": str(exc)[:200]})
                return
    global _local_global
    with _local_lock:
        _local_active[res.key] = max(0, _local_active[res.key] - 1)
        _local_global = max(0, _local_global - 1)


def _gkey() -> str:
    return f"{_KEY_PREFIX}:conc:global"


def _ukey(key: str) -> str:
    return f"{_KEY_PREFIX}:conc:user:{key}"


# ---- sliding-window rate limiting -------------------------------------
_local_buckets: dict[str, deque] = defaultdict(deque)
_bucket_lock = threading.Lock()

# KEYS[1]=bucket  ARGV: 1=now 2=window_start 3=limit 4=member
_RATE_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
local n = redis.call('ZCARD', KEYS[1])
if n >= tonumber(ARGV[3]) then return 0 end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
"""


def allow_request(bucket: str, limit: int, window: int) -> bool:
    """Sliding-window limiter. True = allowed, False = over limit.

    On a Redis outage this fails open (allows) so an outage can't lock users out.
    """
    c = _client()
    if c is not None:
        try:
            now = time.time()
            member = f"{now:.6f}:{secrets.token_hex(4)}"
            rc = c.eval(_RATE_LUA, 1, f"{_KEY_PREFIX}:rl:{bucket}",
                        now, now - window, limit, member, window + 1)
            return int(rc) == 1
        except Exception as exc:  # noqa: BLE001 - fail open
            log.warning("rate_redis_failed", extra={"error": str(exc)[:200]})
            return True
    # in-process fallback (sliding window via deque)
    now = time.time()
    with _bucket_lock:
        b = _local_buckets[bucket]
        while b and b[0] < now - window:
            b.popleft()
        if len(b) >= limit:
            return False
        b.append(now)
    return True


def reset_local() -> None:
    """Test helper: clear in-process state."""
    global _local_global
    with _local_lock:
        _local_active.clear()
        _local_global = 0
    with _bucket_lock:
        _local_buckets.clear()
