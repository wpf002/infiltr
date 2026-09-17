"""Native open-redirect detection (low-impact active, single target).

Injects a benign external canary into common redirect parameters and checks
whether the target 30x-redirects (or meta/JS-redirects) off-site to it. All
requests are GET, non-destructive, redirects are NOT followed, and the probe
count is bounded. Only the given target URL is tested — no crawling."""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_MEDIUM
from ..utils import base_url
from ..webutil import fetch

_CANARY_HOST = "example.com"
_CANARY = f"https://{_CANARY_HOST}/infiltr"
# common redirect param names (bounded set)
_PARAMS = ["next", "url", "redirect", "redirect_url", "redirect_uri", "return",
           "return_url", "returnurl", "dest", "destination", "continue", "goto",
           "forward", "out", "target", "redir", "u", "r", "go", "rurl", "checkout_url"]
_META_JS = re.compile(
    r"(?:http-equiv=['\"]?refresh['\"]?[^>]*url=|location\.(?:href|replace|assign)\s*[=(]\s*['\"])"
    r"\s*(https?:)?//?example\.com", re.I)


class OpenRedirectWrapper(NativeWrapper):
    MODULE_NAME = "openredirect"
    CATEGORY = "web"
    DESCRIPTION = "Open-redirect probe on the target URL's redirect parameters (safe canary)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 60

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 12))
        base = base_url(target)
        parsed = urlparse(target if "?" in target else base)
        existing = dict(parse_qsl(parsed.query))
        # test existing query params first (most likely real), then common names
        names = list(dict.fromkeys(list(existing.keys()) + _PARAMS))

        findings: list[Finding] = []
        seen_params: set[str] = set()
        for name in names:
            if name in seen_params:
                continue
            seen_params.add(name)
            probe = self._with_param(parsed, existing, name, _CANARY)
            r = fetch(probe, timeout=timeout, headers=self.auth_headers(), follow_redirects=False)
            hit = self._is_open_redirect(r)
            if hit:
                findings.append(Finding(
                    type="open_redirect", name=f"open redirect via '{name}'", value=probe,
                    detail=f"parameter '{name}' redirects off-site to {_CANARY_HOST} ({hit})",
                    severity=SEV_MEDIUM,
                    metadata={"param": name, "url": probe, "matched_at": probe,
                              "location": r["headers"].get("location", ""),
                              "mechanism": hit, "confidence": 0.8}))
        if not findings:
            findings.append(Finding(type="note", name="open-redirect", value="none",
                                    detail=f"no redirect parameter forwarded to {_CANARY_HOST}",
                                    severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "open_redirect")
        return f"{n} open-redirect parameter(s)." if n else "No open redirect."

    @staticmethod
    def _with_param(parsed, existing: dict, name: str, value: str) -> str:
        q = dict(existing)
        q[name] = value
        return urlunparse(parsed._replace(query=urlencode(q)))

    @staticmethod
    def _is_open_redirect(r: dict) -> str | None:
        status = r.get("status", 0)
        loc = r["headers"].get("location", "") if r.get("headers") else ""
        if 300 <= status < 400 and loc:
            host = urlparse(loc if "//" in loc else "//" + loc.lstrip("/")).hostname or ""
            if host.lower() == _CANARY_HOST or loc.lower().startswith(("//example.com", "https://example.com", "http://example.com")):
                return f"HTTP {status} Location"
        if _META_JS.search(r.get("body", "") or ""):
            return "meta/js refresh"
        return None
