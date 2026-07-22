"""User / API-key / audit-log operations backed by the store's session."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, func, desc

from ..db import session_scope, init_db
from ..models import User, ApiKey, AuditLog
from . import security

ROLES = ("admin", "operator", "viewer")


def user_count() -> int:
    init_db()
    with session_scope() as s:
        return s.scalar(select(func.count()).select_from(User)) or 0


def create_user(email: str, password: str, role: str = "operator") -> dict[str, Any]:
    init_db()
    if role not in ROLES:
        raise ValueError(f"invalid role: {role}")
    # first user is always an admin (bootstrap)
    if user_count() == 0:
        role = "admin"
    with session_scope() as s:
        if s.scalar(select(User).where(User.email == email)):
            raise ValueError("email already registered")
        u = User(email=email, hashed_password=security.hash_password(password), role=role)
        s.add(u)
        s.flush()
        return u.to_dict()


def authenticate(email: str, password: str) -> Optional[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        u = s.scalar(select(User).where(User.email == email))
        if u is None or not u.is_active:
            return None
        if not security.verify_password(password, u.hashed_password):
            return None
        return u.to_dict()


def get_user(user_id: int) -> Optional[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        u = s.get(User, user_id)
        return u.to_dict() if u else None


def list_users() -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        return [u.to_dict() for u in s.scalars(select(User).order_by(User.id)).all()]


def update_user(user_id: int, role: str | None = None, is_active: bool | None = None) -> Optional[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        u = s.get(User, user_id)
        if u is None:
            return None
        if role is not None:
            if role not in ROLES:
                raise ValueError("invalid role")
            u.role = role
        if is_active is not None:
            u.is_active = is_active
        s.flush()
        return u.to_dict()


def delete_user(user_id: int) -> bool:
    init_db()
    with session_scope() as s:
        u = s.get(User, user_id)
        if u is None:
            return False
        s.delete(u)
        return True


def issue_tokens(user: dict[str, Any]) -> dict[str, str]:
    return {
        "access_token": security.create_token(user["id"], user["role"], "access"),
        "refresh_token": security.create_token(user["id"], user["role"], "refresh"),
        "token_type": "bearer",
    }


# ---- API keys ---------------------------------------------------------
def create_api_key(user_id: int, name: str = "") -> dict[str, Any]:
    init_db()
    full, prefix, key_hash = security.generate_api_key()
    with session_scope() as s:
        k = ApiKey(user_id=user_id, name=name, prefix=prefix, key_hash=key_hash)
        s.add(k)
        s.flush()
        d = k.to_dict()
    d["api_key"] = full  # shown once
    return d


def list_api_keys(user_id: int) -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        stmt = select(ApiKey).where(ApiKey.user_id == user_id).order_by(ApiKey.id)
        return [k.to_dict() for k in s.scalars(stmt).all()]


def revoke_api_key(user_id: int, key_id: int) -> bool:
    init_db()
    with session_scope() as s:
        k = s.get(ApiKey, key_id)
        if k is None or k.user_id != user_id:
            return False
        k.active = False
        return True


def resolve_api_key(full_key: str) -> Optional[dict[str, Any]]:
    """Return the owning user dict for a valid, active API key."""
    init_db()
    key_hash = security.hash_api_key(full_key)
    with session_scope() as s:
        k = s.scalar(select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active == True))  # noqa: E712
        if k is None:
            return None
        k.last_used = datetime.now(timezone.utc)
        u = s.get(User, k.user_id)
        return u.to_dict() if u and u.is_active else None


# ---- audit ------------------------------------------------------------
def audit(action: str, actor: str = "", user_id: int | None = None, detail: str = "", target: str | None = None) -> None:
    init_db()
    with session_scope() as s:
        s.add(AuditLog(action=action, actor=actor, user_id=user_id, detail=detail, target=target))


def list_audit(limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        stmt = select(AuditLog).order_by(desc(AuditLog.id)).limit(limit)
        return [a.to_dict() for a in s.scalars(stmt).all()]
