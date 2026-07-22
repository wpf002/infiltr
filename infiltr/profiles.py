"""Scan profiles — named, reusable module selections + per-module options.

Two tiers:
  * built-ins (defined here, read-only, no id)
  * user profiles (stored in the DB via the store, addressable by id)

Resolution precedence for a scan: explicit `modules` > named `profile` > all.
"""
from __future__ import annotations

from typing import Any, Optional

BUILTIN_PROFILES: dict[str, dict] = {
    "full": {
        "description": "Every registered module",
        "modules": [],  # empty = all
        "options": {},
    },
    "quick": {
        "description": "Fast fingerprint: nmap + whatweb",
        "modules": ["nmap", "whatweb"],
        "options": {"nmap": {"ports": "top1000"}},
    },
    "full-recon": {
        "description": "All reconnaissance modules",
        "modules": ["nmap", "theharvester", "whatweb", "httpx", "subfinder", "dnsx", "wafw00f"],
        "options": {},
    },
    "web-audit": {
        "description": "All web application testing modules",
        "modules": ["feroxbuster", "ffuf", "gobuster", "nikto", "sqlmap", "wfuzz",
                    "xsstrike", "dalfox", "nuclei", "sslscan", "wpscan"],
        "options": {},
    },
    "vuln-scan": {
        "description": "Templated vuln scanning + TLS audit",
        "modules": ["nuclei", "testssl", "sslscan"],
        "options": {},
    },
    "auth-test": {
        "description": "Credential attacks only",
        "modules": ["hydra"],
        "options": {},
    },
}


def builtin_list() -> list[dict]:
    return [
        {"id": None, "name": n, "builtin": True, "target": None, **cfg}
        for n, cfg in BUILTIN_PROFILES.items()
    ]


def all_profiles(user_id: Optional[int] = None) -> list[dict]:
    """Built-ins followed by user-defined DB profiles."""
    from . import store
    return builtin_list() + store.list_profiles(user_id=user_id)


def get_profile(name_or_id, user_id: Optional[int] = None) -> Optional[dict]:
    """Look up a profile by built-in name or by DB id/name."""
    if isinstance(name_or_id, str) and name_or_id in BUILTIN_PROFILES:
        return {"id": None, "name": name_or_id, "builtin": True, "target": None, **BUILTIN_PROFILES[name_or_id]}
    from . import store
    if isinstance(name_or_id, int) or (isinstance(name_or_id, str) and name_or_id.isdigit()):
        return store.get_profile(int(name_or_id), user_id=user_id)
    return store.get_profile_by_name(str(name_or_id), user_id=user_id)


def resolve_modules(profile: Optional[str], modules: Optional[list[str]], user_id: Optional[int] = None):
    """Return an explicit module list (or None = all)."""
    if modules:
        return modules
    if profile:
        prof = get_profile(profile, user_id=user_id)
        if prof and prof.get("modules"):
            return list(prof["modules"])
    return None


def resolve_options(profile: Optional[str], user_id: Optional[int] = None) -> dict[str, Any]:
    if profile:
        prof = get_profile(profile, user_id=user_id)
        if prof:
            return prof.get("options") or {}
    return {}
