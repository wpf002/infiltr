"""Native broken-access-control detection for a single protected endpoint.

Differential oracle, no guessing: the scan's own auth is the legitimate identity.
For the target URL we fetch it (1) authenticated and (2) with NO credentials. A
broken access control is confirmed only when the unauthenticated request gets the
SAME protected body the authenticated one does AND that body carries private
markers (a logged-in-only page: logout link, account/balance, an email address,
an API key). A correctly-protected endpoint returns 401/403/redirect to the
anonymous request; a genuinely public page has no private markers, so neither
trips a finding.

Needs the scan auth (context.auth) to know what "authenticated" looks like.
Without it the module emits a note and reports nothing.
"""
from __future__ import annotations

import re

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..webutil import fetch

# markers that a body is private / logged-in-only, not a public page
_PRIVATE = re.compile(
    r"(log ?out|sign ?out|my account|my profile|dashboard|"
    r"api[_-]?key|access[_-]?token|secret[_-]?key|"
    r"\bbalance\b|\bwallet\b|payout|\bssn\b|two[- ]?factor|"
    r"[\w.+-]+@[\w-]+\.[a-z]{2,})",
    re.I,
)
_LOGIN_HINT = re.compile(
    r"(please (log|sign) ?in|unauthori[sz]ed|forbidden|access denied|401|403|session expired)",
    re.I,
)


class BacWrapper(NativeWrapper):
    MODULE_NAME = "bac"
    CATEGORY = "web"
    DESCRIPTION = "Broken access control: proves a protected page is served without auth (needs scan auth)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 45

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 15))
        auth = self.auth_headers()

        if not auth:
            return [Finding(type="note", name="bac",
                            value="skipped: no scan auth",
                            detail="BAC needs context.auth.headers (the authenticated identity) to tell protected from public",
                            severity=SEV_INFO)]

        # 1) authenticated view — ground truth of the protected content
        authed = fetch(target, timeout=timeout, headers=auth)
        # 2) anonymous view — what an attacker with no credentials sees
        anon = fetch(target, timeout=timeout, headers={})

        if self._is_broken(authed, anon):
            return [Finding(
                type="bac", name="Broken access control", value=target,
                detail="an unauthenticated request retrieved the same private, logged-in-only content as the authenticated one",
                severity=SEV_HIGH,
                metadata={"url": target, "matched_at": target,
                          "authed_status": authed.get("status"), "anon_status": anon.get("status"),
                          "confidence": 0.85, "confirmed": True})]
        return [Finding(type="note", name="bac", value="not vulnerable",
                        detail="the endpoint requires auth, or is genuinely public (no private markers)",
                        severity=SEV_INFO, metadata={"url": target})]

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "bac")
        return f"{n} broken-access-control issue(s)." if n else "No BAC confirmed."

    @staticmethod
    def _is_broken(authed: dict, anon: dict) -> bool:
        if authed.get("status") != 200 or anon.get("status") != 200:
            return False
        ab = authed.get("body", "") or ""
        nb = anon.get("body", "") or ""
        if len(ab) < 64 or _LOGIN_HINT.search(nb[:400]):
            return False
        # the authenticated view must actually be private content...
        if not _PRIVATE.search(ab):
            return False
        # ...and the anonymous request must have gotten that same private content.
        # Exact match, or the private markers present in the anon body too (handles
        # a trivially-varying timestamp/nonce while still proving the leak).
        if nb == ab:
            return True
        return _PRIVATE.search(nb) is not None and _similar(ab, nb)


def _similar(a: str, b: str) -> bool:
    """Cheap length-ratio check: the two bodies are the same page modulo small diffs."""
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return False
    return min(la, lb) / max(la, lb) >= 0.95
