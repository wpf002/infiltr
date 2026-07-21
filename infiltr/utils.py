"""Shared helpers: target normalization, timing, formatting."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def has_scheme(target: str) -> bool:
    return bool(_SCHEME_RE.match(target.strip()))


def normalize_url(target: str, default_scheme: str = "http") -> str:
    """Return a well-formed URL. Adds a scheme if missing, keeps the path."""
    t = target.strip()
    if not has_scheme(t):
        t = f"{default_scheme}://{t}"
    parsed = urlparse(t)
    # Rebuild to drop stray whitespace / normalize.
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""
    url = f"{parsed.scheme}://{netloc}{path}"
    return url.rstrip("/") if path in ("", "/") else url


def hostname(target: str) -> str:
    """Extract a bare host (no scheme, no port, no path) for host-oriented tools."""
    t = target.strip()
    if not has_scheme(t):
        t = f"http://{t}"
    host = urlparse(t).hostname or ""
    return host


def host_port(target: str) -> tuple[str, int | None]:
    t = target.strip()
    if not has_scheme(t):
        t = f"http://{t}"
    p = urlparse(t)
    return (p.hostname or "", p.port)


def base_url(target: str) -> str:
    """Scheme + host + port only, no path — for tools that append their own paths."""
    t = target.strip()
    if not has_scheme(t):
        t = f"http://{t}"
    p = urlparse(t)
    netloc = p.netloc or p.path
    return f"{p.scheme}://{netloc}".rstrip("/")


def is_ip(target: str) -> bool:
    host = hostname(target)
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def truncate(text: str, limit: int = 20000) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
