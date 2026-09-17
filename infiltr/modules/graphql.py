"""Native GraphQL introspection detection (low-impact active, single target).

Probes a bounded set of common GraphQL endpoints and sends one introspection
query. If the server returns its schema, introspection is enabled — an
information-disclosure issue that also maps the attack surface. Non-destructive:
read-only introspection, no mutations. Only paths under the given target host."""
from __future__ import annotations

import json
from urllib.parse import urljoin

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_MEDIUM
from ..utils import base_url
from ..webutil import fetch

_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query",
          "/api/graphql/v1", "/gql", "/graphql/console", "/index.php?graphql"]
# minified introspection query — just enough to prove the schema is exposed
_INTROSPECT = json.dumps({"query": "{__schema{queryType{name} types{name kind}}}"})


class GraphqlWrapper(NativeWrapper):
    MODULE_NAME = "graphql"
    CATEGORY = "web"
    DESCRIPTION = "GraphQL introspection detection on common endpoints (read-only)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 60

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 12))
        base = base_url(target)
        findings: list[Finding] = []
        tested = 0
        for path in _PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            tested += 1
            r = fetch(url, method="POST", timeout=timeout, data=_INTROSPECT,
                      headers={**self.auth_headers(), "content-type": "application/json",
                               "accept": "application/json"})
            body = r.get("body", "") or ""
            if r.get("status") not in (200, 400) or "__schema" not in body:
                continue
            try:
                data = json.loads(body)
            except ValueError:
                continue
            schema = (data.get("data") or {}).get("__schema")
            if isinstance(schema, dict) and schema.get("types"):
                type_count = len(schema.get("types") or [])
                findings.append(Finding(
                    type="graphql_introspection", name="GraphQL introspection enabled", value=url,
                    detail=f"introspection returned the full schema ({type_count} types) — attack surface disclosure",
                    severity=SEV_MEDIUM,
                    metadata={"url": url, "matched_at": url, "types": type_count, "confidence": 0.8}))
                break  # one endpoint is enough
        if not findings:
            findings.append(Finding(type="note", name="graphql", value="none",
                                    detail=f"no GraphQL endpoint with introspection ({tested} paths tried)",
                                    severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "graphql_introspection")
        return "GraphQL introspection exposed." if n else "No exposed GraphQL introspection."
