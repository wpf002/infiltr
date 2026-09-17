"""Native secrets-exposure scanner: exposed sensitive files + secret patterns in
inline/linked JavaScript. Covers the gitleaks/trufflehog intent for a live web
target (which serves URLs, not a git repo)."""
from __future__ import annotations

import re

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL
from ..utils import base_url
from ..webutil import fetch

# path -> (severity, description). Requested once each; a hit is a real exposure.
_EXPOSED_FILES = {
    "/.git/config": (SEV_HIGH, "exposed .git repository config"),
    "/.git/HEAD": (SEV_HIGH, "exposed .git repository"),
    "/.env": (SEV_CRITICAL, "exposed .env (application secrets)"),
    "/.aws/credentials": (SEV_CRITICAL, "exposed AWS credentials"),
    "/config.json": (SEV_MEDIUM, "exposed config.json"),
    "/.npmrc": (SEV_HIGH, "exposed .npmrc (may contain tokens)"),
    "/.dockercfg": (SEV_HIGH, "exposed docker registry credentials"),
    "/wp-config.php.bak": (SEV_CRITICAL, "exposed WordPress config backup"),
    "/backup.sql": (SEV_HIGH, "exposed database dump"),
    "/.DS_Store": (SEV_LOW, "exposed .DS_Store (directory listing leak)"),
}

# secret patterns in served JS/text (kept high-precision to limit false positives)
_SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("github-token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("stripe-secret-key", re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("generic-api-key", re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
]
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


class SecretsWrapper(NativeWrapper):
    MODULE_NAME = "secrets"
    CATEGORY = "web"
    DESCRIPTION = "Exposed sensitive files + secret patterns in served JavaScript"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 60

    def collect(self, target: str) -> list[Finding]:
        root = base_url(target)
        timeout = int(self.options.get("timeout", 12))
        findings: list[Finding] = []

        for path, (sev, desc) in _EXPOSED_FILES.items():
            r = fetch(root + path, timeout=timeout)
            if r["status"] == 200 and r["body"] and not _looks_like_html_error(r["body"]):
                findings.append(Finding(type="exposure", name=path, value=f"HTTP 200",
                                        detail=desc, severity=sev, metadata={"url": r["url"]}))

        # fetch the homepage, scan it + a bounded number of linked scripts for secrets
        home = fetch(root, timeout=timeout)
        docs = [(home["url"], home["body"])]
        for src in _SCRIPT_SRC.findall(home["body"])[:12]:
            js_url = _abs(root, src)
            if js_url:
                jr = fetch(js_url, timeout=timeout)
                if jr["status"] == 200:
                    docs.append((jr["url"], jr["body"]))

        seen: set[str] = set()
        for doc_url, body in docs:
            for label, pat in _SECRET_PATTERNS:
                for m in pat.findall(body or ""):
                    val = m if isinstance(m, str) else (m[0] if m else "")
                    key = f"{label}:{val[:32]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        type="secret", name=label, value=_redact(val),
                        detail=f"potential secret in {doc_url}", severity=SEV_HIGH,
                        metadata={"url": doc_url}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        exp = sum(1 for f in findings if f.type == "exposure")
        sec = sum(1 for f in findings if f.type == "secret")
        return f"{exp} exposed file(s), {sec} potential secret(s)."


def _looks_like_html_error(body: str) -> bool:
    head = body[:200].lower()
    return "<html" in head or "<!doctype" in head


def _redact(v: str) -> str:
    return v[:6] + "…" + v[-4:] if len(v) > 14 else v[:4] + "…"


def _abs(root: str, src: str) -> str | None:
    if src.startswith("http"):
        return src
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("/"):
        return root + src
    return root + "/" + src
