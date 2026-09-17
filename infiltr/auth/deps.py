"""FastAPI dependencies for auth, RBAC, and per-user rate limiting.

Auth is OPT-IN via INFILTR_AUTH=1. When disabled (default), endpoints work
anonymously (user_id=None) so local/dev use and the existing test-suite are
unaffected. When enabled, a valid Bearer JWT or `X-API-Key` is required and all
data is scoped to the authenticated user.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request

from . import security, service
from .. import shared_state

AUTH_ENABLED = os.environ.get("INFILTR_AUTH", "0") in ("1", "true", "True")
# When disabled, only the first (bootstrap admin) account may self-register; after
# that, accounts must be created by an admin. Recommended for public deployments.
OPEN_REGISTRATION = os.environ.get("INFILTR_OPEN_REGISTRATION", "1") in ("1", "true", "True")
RATE_LIMIT = int(os.environ.get("INFILTR_RATE_LIMIT", "60"))       # requests
RATE_WINDOW = int(os.environ.get("INFILTR_RATE_WINDOW", "60"))     # seconds

_ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def _resolve_user(authorization: Optional[str], x_api_key: Optional[str]) -> Optional[dict]:
    if x_api_key:
        return service.resolve_api_key(x_api_key)
    if authorization and authorization.lower().startswith("bearer "):
        payload = security.decode_token(authorization.split(" ", 1)[1])
        if payload and payload.get("type") == "access":
            return service.get_user(int(payload["sub"]))
    return None


async def current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> Optional[dict]:
    """Optional user. None when auth is disabled or no credentials are presented."""
    user = _resolve_user(authorization, x_api_key)
    if AUTH_ENABLED and user is None:
        raise HTTPException(401, "authentication required")
    return user


async def require_user(user: Optional[dict] = Depends(current_user)) -> dict:
    if user is None:
        raise HTTPException(401, "authentication required")
    return user


def require_role(min_role: str):
    async def _dep(user: dict = Depends(require_user)) -> dict:
        if _ROLE_RANK.get(user["role"], 0) < _ROLE_RANK.get(min_role, 99):
            raise HTTPException(403, f"requires {min_role} role")
        return user
    return _dep


def rate_limit(user: Optional[dict] = Depends(current_user)) -> None:
    """Sliding-window per-user (or anonymous) rate limit. Cross-node via Redis
    when REDIS_URL is set, else in-process per replica."""
    if not AUTH_ENABLED:
        return
    key = str(user["id"]) if user else "anon"
    if not shared_state.allow_request(f"user:{key}", RATE_LIMIT, RATE_WINDOW):
        raise HTTPException(429, "rate limit exceeded")


def user_id_of(user: Optional[dict]) -> Optional[int]:
    return user["id"] if user else None


# ---- auth-endpoint brute-force limiter (always on, per client IP) -----
AUTH_RATE_LIMIT = int(os.environ.get("INFILTR_AUTH_RATE_LIMIT", "10"))   # attempts
AUTH_RATE_WINDOW = int(os.environ.get("INFILTR_AUTH_RATE_WINDOW", "300"))  # seconds


def _client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


def auth_rate_limit(request: Request) -> None:
    """Per-IP limiter for /auth/login and /auth/register (credential stuffing).
    Cross-node via Redis when REDIS_URL is set, else in-process per replica."""
    ip = _client_ip(request)
    if not shared_state.allow_request(f"auth:{ip}", AUTH_RATE_LIMIT, AUTH_RATE_WINDOW):
        raise HTTPException(429, "too many attempts; slow down")
