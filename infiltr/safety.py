"""Input sanitization + target scope enforcement + SSRF protection.

Scans never use a shell (commands are argv lists), but a public multi-tenant
deployment still has to refuse:
  - argument injection (targets/options that inject argv flags or shell metachars)
  - out-of-scope targets (allow/block lists)
  - SSRF to internal infrastructure (loopback/RFC1918/link-local/metadata), gated
    by INFILTR_BLOCK_PRIVATE so the local dev lab still works.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import socket

from .utils import hostname, host_port

# characters that have no business in a hostname/URL target
_FORBIDDEN = re.compile(r"[;&|`$><\n\r\t\"'\\ ]")
# metacharacters / flag-injection in a scan-option value
_OPT_BAD = re.compile(r"[;&|`$><\n\r\t\"'\\]")


class ScopeError(ValueError):
    """Raised when a target is malformed or out of scope."""


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) in ("1", "true", "True")


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()]


def allowlist() -> list[str]:
    return _env_list("INFILTR_ALLOWLIST")


def blocklist() -> list[str]:
    default = ["169.254.169.254", "metadata.google.internal"]
    return _env_list("INFILTR_BLOCKLIST") or default


def block_private() -> bool:
    """Block loopback/RFC1918/link-local/reserved targets (public SaaS)."""
    return _flag("INFILTR_BLOCK_PRIVATE")


def _host_matches(host: str, pattern: str) -> bool:
    if not host:
        return False
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(host) in net
    except ValueError:
        pass
    return fnmatch.fnmatch(host.lower(), pattern.lower())


def sanitize_target(target: str) -> str:
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


def _resolve_ips(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve host (or IP literal) to every address it maps to."""
    # normalize an IP literal (catches decimal/hex/octal encodings too)
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    ips: list = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            try:
                ips.append(ipaddress.ip_address(sockaddr[0]))
            except ValueError:
                continue
    except OSError as exc:
        raise ScopeError(f"could not resolve target host '{host}': {exc}")
    return ips


def _is_internal(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def check_scope(target: str) -> str:
    """Sanitize + enforce allow/block lists + SSRF guard. Returns target or raises."""
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

    if block_private():
        ips = _resolve_ips(host)
        if not ips:
            raise ScopeError(f"target '{host}' did not resolve")
        for ip in ips:
            if _is_internal(ip):
                raise ScopeError(
                    f"target '{host}' resolves to a private/internal address ({ip}); "
                    "scanning internal infrastructure is not allowed"
                )
    return t


def is_in_scope(target: str) -> bool:
    try:
        check_scope(target)
        return True
    except ScopeError:
        return False


# ---- scan-option sanitization (argument-injection defense) ------------
# When INFILTR_LOCK_OPTIONS is on (public SaaS), users may only tweak this
# curated, non-dangerous set per module; every other key is dropped and the
# safe server default is used. Dangerous keys (flags, scripts, module, payload,
# opts, userlist, passlist, path) are never user-controllable.
SAFE_USER_OPTIONS: dict[str, set[str]] = {
    "nmap": {"ports"},
    "nuclei": {"severity", "tags", "rate_limit"},
    "masscan": {"ports"},
    "feroxbuster": {"depth"},
    "whatweb": {"aggression"},
    "theharvester": {"sources", "limit"},
    "sqlmap": {"level", "risk"},
    "wpscan": set(),
    # everything unlisted -> no user-tweakable options
}


def lock_options() -> bool:
    return _flag("INFILTR_LOCK_OPTIONS")


def _check_value(where: str, v) -> None:
    if isinstance(v, str):
        if v.startswith("-") or _OPT_BAD.search(v):
            raise ScopeError(f"option {where} has an unsafe value")
    elif isinstance(v, (list, tuple)):
        for item in v:
            _check_value(where, item)
    elif isinstance(v, dict):
        for kk, vv in v.items():
            _check_value(f"{where}.{kk}", vv)


def sanitize_options(options: dict | None) -> dict:
    """Clean user-supplied per-module options. Raises ScopeError on injection.

    Locked mode keeps only SAFE_USER_OPTIONS keys; unlocked mode keeps all keys
    but still rejects flag/metachar injection in every value.
    """
    if not options:
        return {}
    locked = lock_options()
    clean: dict = {}
    for mod, opts in options.items():
        if not isinstance(opts, dict):
            continue
        allowed = SAFE_USER_OPTIONS.get(mod, set())
        safe: dict = {}
        for k, v in opts.items():
            if locked and k not in allowed:
                continue  # drop dangerous/unknown key -> server default is used
            _check_value(f"{mod}.{k}", v)
            safe[k] = v
        if safe:
            clean[mod] = safe
    return clean
