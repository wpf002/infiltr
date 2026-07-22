"""Scan profiles — named, reusable module selections.

Phase 3 ships the built-ins + resolver; Phase 6 layers user-defined profiles and
CRUD on top of this same registry.
"""
from __future__ import annotations

from typing import Optional

BUILTIN_PROFILES: dict[str, dict] = {
    "full": {
        "description": "Every registered module",
        "modules": [],  # empty = all
    },
    "quick": {
        "description": "Fast fingerprint: nmap + whatweb",
        "modules": ["nmap", "whatweb"],
    },
    "full-recon": {
        "description": "All reconnaissance modules",
        "modules": ["nmap", "theharvester", "whatweb"],
    },
    "web-audit": {
        "description": "All web application testing modules",
        "modules": ["feroxbuster", "ffuf", "gobuster", "nikto", "sqlmap", "wfuzz", "xsstrike"],
    },
    "auth-test": {
        "description": "Credential attacks only",
        "modules": ["hydra"],
    },
}


def resolve_modules(profile: Optional[str], modules: Optional[list[str]]) -> Optional[list[str]]:
    """Return an explicit module list.

    Precedence: explicit `modules` > `profile` > None (which the engine treats as all).
    """
    if modules:
        return modules
    if profile:
        prof = BUILTIN_PROFILES.get(profile)
        if prof and prof["modules"]:
            return list(prof["modules"])
    return None


def list_profiles() -> list[dict]:
    return [{"name": name, **cfg} for name, cfg in BUILTIN_PROFILES.items()]
