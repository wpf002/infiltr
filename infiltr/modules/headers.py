"""Native security-header + CORS misconfiguration analyzer (no external tool)."""
from __future__ import annotations

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH
from ..utils import base_url
from ..webutil import fetch

# header -> (severity, why it matters when missing)
_SECURITY_HEADERS = {
    "strict-transport-security": (SEV_MEDIUM, "no HSTS — connection can be downgraded to HTTP"),
    "content-security-policy": (SEV_MEDIUM, "no CSP — weaker defense against XSS/injection"),
    "x-frame-options": (SEV_LOW, "no anti-clickjacking header (X-Frame-Options / CSP frame-ancestors)"),
    "x-content-type-options": (SEV_LOW, "no nosniff — MIME-sniffing allowed"),
    "referrer-policy": (SEV_INFO, "no Referrer-Policy — referrer may leak to third parties"),
}
_LEAKY_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-generator"}


class HeadersWrapper(NativeWrapper):
    MODULE_NAME = "headers"
    CATEGORY = "web"
    DESCRIPTION = "Security-header + CORS misconfiguration analysis"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 30

    def collect(self, target: str) -> list[Finding]:
        url = base_url(target)
        r = fetch(url, timeout=int(self.options.get("timeout", 20)))
        if r["status"] == 0:
            return [Finding(type="note", name="unreachable", value=r.get("error", "")[:120], severity=SEV_INFO)]
        h = r["headers"]
        findings: list[Finding] = []

        for name, (sev, why) in _SECURITY_HEADERS.items():
            if name not in h:
                # clickjacking is also covered by CSP frame-ancestors
                if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
                    continue
                findings.append(Finding(type="missing_header", name=name, value="missing",
                                        detail=why, severity=sev,
                                        metadata={"url": r["url"]}))

        for name in _LEAKY_HEADERS:
            if h.get(name):
                findings.append(Finding(type="header", name=name, value=h[name][:120],
                                        detail="server/version banner disclosure", severity=SEV_INFO,
                                        metadata={"url": r["url"]}))

        # CORS: reflect an arbitrary Origin and check the response
        probe = fetch(url, timeout=15, headers={"Origin": "https://evil.example.com"})
        aco = probe["headers"].get("access-control-allow-origin", "")
        acc = probe["headers"].get("access-control-allow-credentials", "").lower()
        if aco == "https://evil.example.com" or aco == "*":
            sev = SEV_HIGH if (aco != "*" and acc == "true") else SEV_MEDIUM if aco != "*" else SEV_LOW
            findings.append(Finding(
                type="cors", name="permissive CORS", value=aco,
                detail=("reflects arbitrary Origin with credentials — cross-origin data theft"
                        if acc == "true" and aco != "*" else "permissive Access-Control-Allow-Origin"),
                severity=sev, metadata={"url": r["url"], "allow_credentials": acc}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        miss = sum(1 for f in findings if f.type == "missing_header")
        cors = sum(1 for f in findings if f.type == "cors")
        return f"{miss} missing security header(s), {cors} CORS issue(s)."
