"""Minimal 5-field cron parser/matcher (no third-party dependency).

Fields: minute hour day-of-month month day-of-week
Supports: ``*``  ``*/n``  ``a-b``  ``a-b/n``  ``a,b,c``  and single values.
day-of-week: 0-6 (0 = Sunday); 7 also accepted as Sunday.
"""
from __future__ import annotations

from datetime import datetime

_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]


def _expand(field: str, lo: int, hi: int) -> set[int]:
    values: set[int] = set()
    for part in field.split(","):
        step = 1
        if "/" in part:
            base, step_s = part.split("/", 1)
            step = int(step_s)
        else:
            base = part
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            start, end = int(a), int(b)
        else:
            start = end = int(base)
        for v in range(start, end + 1, step):
            if lo <= v <= hi:
                values.add(v)
    return values


def _parse(expr: str) -> list[set[int]]:
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError("cron expression must have 5 fields: min hr dom mon dow")
    parsed = []
    for field, (lo, hi) in zip(fields, _RANGES):
        f = field.replace("7", "0") if (lo, hi) == (0, 6) and field == "7" else field
        parsed.append(_expand(f, lo, hi))
    return parsed


def validate_cron(expr: str) -> bool:
    try:
        _parse(expr)
        return True
    except Exception:  # noqa: BLE001
        return False


def cron_matches(expr: str, when: datetime) -> bool:
    """True if `when` (minute resolution) satisfies the cron expression."""
    minute, hour, dom, month, dow = _parse(expr)
    # cron: if either DOM or DOW is restricted, match on OR of the two (standard behavior)
    dow_now = (when.weekday() + 1) % 7  # Python Mon=0 -> cron Sun=0
    day_ok_dom = when.day in dom
    day_ok_dow = dow_now in dow
    full_dom = dom == set(range(1, 32))
    full_dow = dow == set(range(0, 7))
    if full_dom and full_dow:
        day_ok = True
    elif full_dom:
        day_ok = day_ok_dow
    elif full_dow:
        day_ok = day_ok_dom
    else:
        day_ok = day_ok_dom or day_ok_dow
    return when.minute in minute and when.hour in hour and when.month in month and day_ok
