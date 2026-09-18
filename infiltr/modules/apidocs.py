"""Native exposed-API-spec detection (Tier 1, read-only).

Probes common Swagger/OpenAPI spec paths. An exposed spec maps the whole API
attack surface (and sometimes leaks internal/admin endpoints) — a real
information-disclosure finding. Read-only GETs, bounded path set."""
from __future__ import annotations

import json
from urllib.parse import urljoin

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_MEDIUM
from ..utils import base_url
from ..webutil import fetch

_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
          "/swagger/v1/swagger.json", "/.well-known/openapi.json", "/api/swagger.json",
          "/api/openapi.json", "/swagger-ui/swagger.json", "/api/v1/openapi.json"]


class ApiDocsWrapper(NativeWrapper):
    MODULE_NAME = "apidocs"
    CATEGORY = "web"
    DESCRIPTION = "Exposed API specification (Swagger/OpenAPI) detection"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 60

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 12))
        base = base_url(target)
        findings: list[Finding] = []
        for path in _PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            r = fetch(url, timeout=timeout, headers=self.auth_headers())
            if r.get("status") != 200:
                continue
            body = r.get("body", "") or ""
            if not any(k in body for k in ('"swagger"', '"openapi"', '"paths"')):
                continue
            try:
                doc = json.loads(body)
            except ValueError:
                continue
            paths = doc.get("paths") if isinstance(doc, dict) else None
            if isinstance(paths, dict) and paths:
                findings.append(Finding(
                    type="apidocs", name="exposed API specification", value=url,
                    detail=f"OpenAPI/Swagger spec exposed with {len(paths)} endpoints — attack-surface disclosure",
                    severity=SEV_MEDIUM,
                    metadata={"url": url, "matched_at": url, "endpoints": len(paths), "confidence": 0.75}))
                break
        if not findings:
            findings.append(Finding(type="note", name="apidocs", value="none",
                                    detail="no exposed API specification found", severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return "Exposed API spec." if any(f.type == "apidocs" for f in findings) else "No exposed API spec."
