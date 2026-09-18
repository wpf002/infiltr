"""Native open cloud-storage bucket detection (Tier 1, read-only).

Extracts S3/GCS bucket references from the target's page, then checks each
bucket root for public directory listing. A world-listable bucket is real data
exposure. Read-only GETs, bounded count."""
from __future__ import annotations

import re

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..webutil import fetch

_BUCKET_RE = re.compile(
    r"(?:https?://)?("
    r"[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com"
    r"|s3[.\-][a-z0-9.\-]*amazonaws\.com/[a-z0-9._\-]+"
    r"|storage\.googleapis\.com/[a-z0-9._\-]+"
    r"|[a-z0-9._\-]+\.storage\.googleapis\.com)", re.I)


class BucketsWrapper(NativeWrapper):
    MODULE_NAME = "buckets"
    CATEGORY = "web"
    DESCRIPTION = "Open S3/GCS bucket detection from references on the target"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 60

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 12))
        r = fetch(target, timeout=timeout, headers=self.auth_headers())
        body = r.get("body", "") or ""
        buckets = {m.group(1).lower() for m in _BUCKET_RE.finditer(body)}
        findings: list[Finding] = []
        for b in list(buckets)[:15]:
            url = b if b.startswith("http") else "https://" + b
            rr = fetch(url, timeout=timeout)
            body2 = rr.get("body", "") or ""
            if rr.get("status") == 200 and ("<ListBucketResult" in body2 or "<Contents>" in body2):
                findings.append(Finding(
                    type="exposure", name="publicly-listable cloud bucket", value=url,
                    detail="storage bucket lists its contents to anyone — data exposure",
                    severity=SEV_HIGH,
                    metadata={"url": url, "matched_at": url, "confidence": 0.85}))
        if not findings:
            findings.append(Finding(type="note", name="buckets", value="none",
                                    detail="no open bucket referenced by the target", severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "exposure")
        return f"{n} open bucket(s)." if n else "No open bucket."
