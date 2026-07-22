"""Crypto primitives — HS256 JWT, PBKDF2 password hashing, API keys (stdlib only).

Uses bcrypt via passlib when available; otherwise a strong PBKDF2-HMAC-SHA256
scheme. JWTs are HS256, signed/verified with the stdlib (hmac + hashlib) so there
is no hard third-party dependency.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

SECRET_KEY = os.environ.get("INFILTR_SECRET_KEY", "").strip()
if not SECRET_KEY:
    # ephemeral per-process key; set INFILTR_SECRET_KEY in production
    SECRET_KEY = secrets.token_urlsafe(48)

ACCESS_TTL = int(os.environ.get("INFILTR_ACCESS_TTL", str(60 * 30)))        # 30 min
REFRESH_TTL = int(os.environ.get("INFILTR_REFRESH_TTL", str(60 * 60 * 24 * 7)))  # 7 days
_PBKDF2_ROUNDS = 240_000


# ---- base64url helpers -----------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- password hashing -------------------------------------------------
try:
    from passlib.context import CryptContext  # type: ignore
    _pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _pwd_ctx.hash("backend-probe")  # ensure the bcrypt backend is actually usable
    _HAS_PASSLIB = True
except Exception:  # noqa: BLE001 — no passlib or no working bcrypt backend
    _pwd_ctx = None
    _HAS_PASSLIB = False


def hash_password(password: str) -> str:
    if _HAS_PASSLIB:
        return _pwd_ctx.hash(password)
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, hashed: str) -> bool:
    if hashed.startswith("pbkdf2_sha256$"):
        try:
            _, rounds, salt_b64, dk_b64 = hashed.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), _b64d(salt_b64), int(rounds))
            return hmac.compare_digest(dk, _b64d(dk_b64))
        except Exception:  # noqa: BLE001
            return False
    if _HAS_PASSLIB:
        try:
            return _pwd_ctx.verify(password, hashed)
        except Exception:  # noqa: BLE001
            return False
    return False


# ---- JWT (HS256) ------------------------------------------------------
def _sign(msg: bytes) -> str:
    return _b64e(hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest())


def create_token(sub: int, role: str, token_type: str = "access", ttl: int | None = None) -> str:
    now = int(time.time())
    if ttl is None:
        ttl = ACCESS_TTL if token_type == "access" else REFRESH_TTL
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "role": role, "type": token_type, "iat": now, "exp": now + ttl,
               "jti": secrets.token_urlsafe(8)}
    seg = f"{_b64e(json.dumps(header).encode())}.{_b64e(json.dumps(payload).encode())}"
    return f"{seg}.{_sign(seg.encode())}"


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        header_b64, payload_b64, sig = token.split(".")
    except ValueError:
        return None
    seg = f"{header_b64}.{payload_b64}"
    if not hmac.compare_digest(sig, _sign(seg.encode())):
        return None
    try:
        payload = json.loads(_b64d(payload_b64))
    except Exception:  # noqa: BLE001
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload


# ---- API keys ---------------------------------------------------------
def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, key_hash). Full key is shown to the user once."""
    raw = secrets.token_urlsafe(32)
    prefix = "inf_" + raw[:6]
    full = f"{prefix}.{raw}"
    key_hash = hashlib.sha256(full.encode()).hexdigest()
    return full, prefix, key_hash


def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode()).hexdigest()


def api_key_prefix(full_key: str) -> str:
    return full_key.split(".")[0] if "." in full_key else full_key[:10]
