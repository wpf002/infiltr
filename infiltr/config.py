"""Per-module default options and global settings.

Every wrapper reads its slice via ``config.for_module(name)``. Values here are
merged with (and overridden by) options passed at scan time.
"""
from __future__ import annotations

import os
from typing import Any

# ---- global -----------------------------------------------------------
GLOBAL: dict[str, Any] = {
    "timeout": int(os.environ.get("INFILTR_TIMEOUT", "300")),
    "wordlist": os.environ.get(
        "INFILTR_WORDLIST", "/usr/share/wordlists/dirb/common.txt"
    ),
    "userlist": os.environ.get("INFILTR_USERLIST", "/usr/share/wordlists/usernames.txt"),
    "passlist": os.environ.get(
        "INFILTR_PASSLIST", "/usr/share/wordlists/rockyou.txt"
    ),
    "threads": int(os.environ.get("INFILTR_THREADS", "20")),
    "xsstrike_path": os.environ.get(
        "INFILTR_XSSTRIKE", os.path.expanduser("~/tools/XSStrike/xsstrike.py")
    ),
}

# ---- per-module defaults ---------------------------------------------
MODULES: dict[str, dict[str, Any]] = {
    "nmap": {
        "ports": "top1000",          # "top1000" | "1-65535" | "80,443"
        "flags": ["-sV", "-T4", "-Pn"],
        "scripts": "default",         # "default" | "vuln" | None
        "timeout": 600,
    },
    "theharvester": {
        "sources": "bing,duckduckgo,crtsh",
        "limit": 200,
        "timeout": 300,
    },
    "whatweb": {
        "aggression": 1,              # 1..4
        "timeout": 120,
    },
    "feroxbuster": {
        "threads": 25,
        "depth": 2,
        "status_codes": [200, 204, 301, 302, 307, 401, 403, 405],
        "timeout": 300,
    },
    "ffuf": {
        "threads": 40,
        "match_codes": "200,204,301,302,307,401,403,405",
        "timeout": 300,
    },
    "gobuster": {
        "threads": 30,
        "status_codes": "200,204,301,302,307,401,403",
        "timeout": 300,
    },
    "nikto": {
        "tuning": None,               # e.g. "x6" ; None = default
        "timeout": 600,
    },
    "sqlmap": {
        "level": 1,
        "risk": 1,
        "batch": True,
        "crawl": 0,
        "timeout": 600,
    },
    "wfuzz": {
        "threads": 30,
        "hide_codes": "404",
        "timeout": 300,
    },
    "xsstrike": {
        "crawl": False,
        "timeout": 300,
    },
    "hydra": {
        "service": "http-get",        # inferred from target when possible
        "threads": 8,
        "timeout": 600,
    },
}


def for_module(name: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return merged config for a module: GLOBAL < MODULES[name] < overrides."""
    merged: dict[str, Any] = {}
    merged.update(GLOBAL)
    merged.update(MODULES.get(name, {}))
    if overrides:
        merged.update({k: v for k, v in overrides.items() if v is not None})
    return merged
