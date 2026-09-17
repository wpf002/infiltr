"""Native JWT weakness detection (passive, single target).

Finds JSON Web Tokens exposed in the target's response body, cookies, or auth
headers, decodes them WITHOUT verifying (no cracking, no requests beyond fetching
the target), and flags real weaknesses: an unsigned `alg:none` token, or a token
with no expiry. Passive and non-destructive."""
from __future__ import annotations

import base64
import binascii
import json
import re

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_MEDIUM, SEV_HIGH
from ..webutil import fetch

_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{0,}")


def _b64url(seg: str) -> dict | None:
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad).decode("utf-8", "replace"))
    except (binascii.Error, ValueError):
        return None


class JwtAuditWrapper(NativeWrapper):
    MODULE_NAME = "jwt_audit"
    CATEGORY = "web"
    DESCRIPTION = "Detect exposed JWTs and flag alg:none / missing-expiry weaknesses (passive)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 30

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 12))
        r = fetch(target, timeout=timeout, headers=self.auth_headers())
        haystack = (r.get("body", "") or "")
        hdrs = r.get("headers", {}) or {}
        haystack += " " + str(hdrs.get("set-cookie", "")) + " " + str(hdrs.get("authorization", ""))

        findings: list[Finding] = []
        seen: set[str] = set()
        for tok in _JWT.findall(haystack):
            head_seg = tok.split(".")[0]
            if head_seg in seen:
                continue
            seen.add(head_seg)
            header = _b64url(head_seg)
            payload = _b64url(tok.split(".")[1]) if "." in tok else None
            if not header:
                continue
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                findings.append(Finding(
                    type="jwt_weakness", name="unsigned JWT (alg:none)", value=tok[:32] + "…",
                    detail="server exposes/accepts a JWT with alg:none — signature is not verified (auth bypass)",
                    severity=SEV_HIGH,
                    metadata={"url": target, "matched_at": target, "alg": alg, "confidence": 0.85}))
            elif isinstance(payload, dict) and "exp" not in payload:
                findings.append(Finding(
                    type="jwt_weakness", name="JWT without expiry", value=tok[:32] + "…",
                    detail=f"exposed JWT (alg={alg or '?'}) has no exp claim — token never expires if leaked",
                    severity=SEV_MEDIUM,
                    metadata={"url": target, "matched_at": target, "alg": alg, "confidence": 0.6}))
        if not findings:
            findings.append(Finding(type="note", name="jwt", value="none",
                                    detail="no weak JWT exposed on the target",
                                    severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "jwt_weakness")
        return f"{n} JWT weakness(es)." if n else "No JWT weakness."
