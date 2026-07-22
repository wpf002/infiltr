"""Input sanitization + target scope enforcement.

Scans never use a shell (commands are argv lists), but we still refuse targets
that look like argument injection or that fall outside the configured scope.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re

from .utils import hostname

# characters that have no business in a hostname/URL target
_FORBIDDEN = re.compile(r"[;&|`$><\n\r\t\"'\\ ]")


class ScopeError(ValueError):
    """Raised when a target is malformed or out of scope."""


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()]


def allowlist() -> list[str]:
    return _env_list("INFILTR_ALLOWLIST")


def blocklist() -> list[str]:
    # sensible defaults: never scan cloud metadata endpoints
    default = ["169.254.169.254", "metadata.google.internal"]
    return _env_list("INFILTR_BLOCKLIST") or default


def _host_matches(host: str, pattern: str) -> bool:
    if not host:
        return False
    # CIDR / IP range
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(host) in net
    except ValueError:
        pass
    # glob (supports *.example.com) or exact
    return fnmatch.fnmatch(host.lower(), pattern.lower())


def sanitize_target(target: str) -> str:
    """Validate a raw target string; return it stripped or raise ScopeError."""
    if not target or not target.strip():
        raise ScopeError("empty target")
    t = target.strip()
    if t.startswith("-"):
        raise ScopeError("target may not start with '-' (argument injection)")
    if _FORBIDDEN.search(t):
        raise ScopeError("target contains forbidden characters")
    if len(t) > 512:
        raise ScopeError("target too long")
    return t


def check_scope(target: str) -> str:
    """Sanitize + enforce allow/block lists. Returns the target or raises ScopeError."""
    t = sanitize_target(target)
    host = hostname(t)
    if not host:
        raise ScopeError("could not parse a host from target")

    for pat in blocklist():
        if _host_matches(host, pat):
            raise ScopeError(f"target '{host}' is blocklisted")

    allow = allowlist()
    if allow and not any(_host_matches(host, pat) for pat in allow):
        raise ScopeError(f"target '{host}' is not in the allowlist")

    return t


def is_in_scope(target: str) -> bool:
    try:
        check_scope(target)
        return True
    except ScopeError:
        return False
