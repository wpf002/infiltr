"""Native IDOR / BOLA detection for a single target (needs two identities).

Confirms broken object-level authorization by proving one identity can read
another's resource. The attacker identity is the scan's own auth; the victim
identity + the victim's object id are supplied via options (Quarry passes them
in the request `context`). Detection compares the attacker's fetch of the
victim's resource against the victim's own fetch of it — an exact match on a
non-trivial, non-error body is a confirmed cross-user read (kills false
positives from public pages or login redirects).

Without a second identity the module does nothing (emits a note), so it never
guesses or fabricates a finding.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..webutil import fetch

_LOGIN_HINT = re.compile(r"(sign in|log ?in|password|unauthori[sz]ed|forbidden|access denied|please log)", re.I)
_NUMERIC_OR_UUID = re.compile(r"^\d+$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class IdorWrapper(NativeWrapper):
    MODULE_NAME = "idor"
    CATEGORY = "web"
    DESCRIPTION = "IDOR/BOLA: proves one identity can read another's object (needs 2 identities)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 60

    def collect(self, target: str) -> list[Finding]:
        victim_headers = self.options.get("victim_headers") or {}
        victim_id = str(self.options.get("victim_id") or "")
        id_param = self.options.get("id_param")  # query param name, or None to substitute a path segment
        timeout = int(self.options.get("timeout", 15))

        if not victim_headers or not victim_id:
            return [Finding(type="note", name="idor",
                            value="skipped: no second identity provided",
                            detail="IDOR needs context.idor.victim_headers + victim_id (attacker = scan auth)",
                            severity=SEV_INFO)]

        victim_url = self._swap_id(target, id_param, victim_id)
        if victim_url is None:
            return [Finding(type="note", name="idor", value="no id location",
                            detail=f"couldn't place victim_id in the target URL (id_param={id_param!r})",
                            severity=SEV_INFO)]

        # 1) victim reads their own resource — ground truth of B's private data
        v = fetch(victim_url, timeout=timeout, headers=victim_headers)
        # 2) attacker (scan identity) reads the SAME resource
        a = fetch(victim_url, timeout=timeout, headers=self.auth_headers())
        # 3) anonymous control: what an unauthenticated request sees. If the victim's
        #    resource equals the anonymous view it's a public/login/error page, not
        #    private data — prevents the "both see the same login page" false positive.
        anon = fetch(victim_url, timeout=timeout, headers={})

        findings: list[Finding] = []
        if self._is_cross_user_read(a, v, anon):
            findings.append(Finding(
                type="idor", name="IDOR / broken object-level auth", value=victim_url,
                detail="the scan identity retrieved another user's resource (attacker body == victim body)",
                severity=SEV_HIGH,
                metadata={"url": victim_url, "matched_at": victim_url, "param": id_param or "path",
                          "victim_id": victim_id, "attacker_status": a.get("status"),
                          "victim_status": v.get("status"), "confidence": 0.9, "confirmed": True}))
        else:
            findings.append(Finding(type="note", name="idor", value="not vulnerable",
                                    detail="attacker could not retrieve the victim's private resource",
                                    severity=SEV_INFO, metadata={"url": victim_url}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "idor")
        return f"{n} IDOR/BOLA issue(s)." if n else "No IDOR confirmed."

    @staticmethod
    def _swap_id(target: str, id_param: str | None, new_id: str) -> str | None:
        p = urlparse(target)
        if id_param:
            q = dict(parse_qsl(p.query))
            if id_param not in q and p.query:
                return None  # named param not present -> don't guess
            q[id_param] = new_id
            return urlunparse(p._replace(query=urlencode(q)))
        # no param named: replace the last numeric/UUID path segment
        segs = p.path.split("/")
        for i in range(len(segs) - 1, -1, -1):
            if _NUMERIC_OR_UUID.match(segs[i]):
                segs[i] = new_id
                return urlunparse(p._replace(path="/".join(segs)))
        return None

    @staticmethod
    def _is_cross_user_read(a: dict, v: dict, anon: dict) -> bool:
        if a.get("status") != 200 or v.get("status") != 200:
            return False
        ab, vb = a.get("body", "") or "", v.get("body", "") or ""
        if len(vb) < 16 or _LOGIN_HINT.search(ab[:400]):
            return False
        if ab != vb:
            return False  # attacker didn't get the victim's exact resource
        # the resource must actually be protected: an anonymous request must NOT
        # already return it (else it's a public/login/error page shared by everyone)
        anon_body = anon.get("body", "") or ""
        if anon.get("status") == 200 and anon_body == vb:
            return False
        return True
