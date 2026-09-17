"""Native SSRF detection via out-of-band callback (single target).

Injects a unique canary URL into SSRF-prone parameters of the target and watches
for the target to call back. Infiltr runs its own ephemeral OOB listener, so
confirmation needs no third-party collaborator — but the target must be able to
reach the listener, so the operator supplies context.ssrf.canary_host (the
address the target sees Infiltr at, e.g. an internal hostname). A callback
carrying the token is a confirmed SSRF; without a callback nothing is reported.

Reachability caveat: works when the target can reach the listener (internal
apps, lab, SSRF-to-internal). For public targets that can't reach a private
listener, point canary_host at a public collaborator you control.
"""
from __future__ import annotations

import http.server
import secrets
import socket
import threading
import time
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..webutil import fetch

# parameters that commonly take a URL/host the server will fetch
_PARAMS = ["url", "uri", "u", "dest", "destination", "redirect", "redirect_uri",
           "callback", "webhook", "feed", "host", "port", "path", "continue",
           "next", "data", "target", "site", "html", "page", "file", "document",
           "resource", "proxy", "image", "imageurl", "img", "source", "load", "to"]


class _Collector(http.server.BaseHTTPRequestHandler):
    hits: set = set()

    def do_GET(self):  # noqa: N802
        tok = self.path.strip("/").split("?", 1)[0].split("/")[0]
        if tok:
            type(self).hits.add(tok)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):  # silence
        return


class SsrfWrapper(NativeWrapper):
    MODULE_NAME = "ssrf"
    CATEGORY = "web"
    DESCRIPTION = "SSRF via out-of-band callback to Infiltr's own canary (needs a reachable canary_host)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 90

    def collect(self, target: str) -> list[Finding]:
        canary_host = str(self.options.get("canary_host") or "").strip()
        wait = int(self.options.get("wait", 6))
        timeout = int(self.options.get("timeout", 12))

        if not canary_host:
            return [Finding(type="note", name="ssrf",
                            value="skipped: no canary_host provided",
                            detail="SSRF needs context.ssrf.canary_host (an address the target can reach Infiltr at)",
                            severity=SEV_INFO)]

        server, port = self._start_listener()
        if server is None:
            return [Finding(type="note", name="ssrf", value="listener failed",
                            detail="could not bind an OOB listener", severity=SEV_INFO)]
        try:
            base_host = canary_host if ":" in canary_host else f"{canary_host}:{port}"
            token_param: dict[str, str] = {}
            p = urlparse(target)
            existing = dict(parse_qsl(p.query))
            names = list(dict.fromkeys(list(existing.keys()) + _PARAMS))
            for name in names:
                token = secrets.token_hex(8)
                token_param[token] = name
                canary = f"http://{base_host}/{token}"
                probe = self._with_param(p, existing, name, canary)
                fetch(probe, timeout=timeout, headers=self.auth_headers())

            deadline = time.monotonic() + wait
            while time.monotonic() < deadline and not _Collector.hits & set(token_param):
                time.sleep(0.3)

            findings: list[Finding] = []
            for token in sorted(_Collector.hits & set(token_param)):
                param = token_param[token]
                findings.append(Finding(
                    type="ssrf", name=f"SSRF via '{param}'", value=target,
                    detail=f"target fetched the canary via parameter '{param}' (out-of-band callback received)",
                    severity=SEV_HIGH,
                    metadata={"url": target, "matched_at": target, "param": param,
                              "canary": f"http://{base_host}/{token}", "confidence": 0.9}))
            if not findings:
                findings.append(Finding(type="note", name="ssrf", value="no callback",
                                        detail="no parameter produced an out-of-band callback",
                                        severity=SEV_INFO))
            return findings
        finally:
            self._stop_listener(server, token_param)

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "ssrf")
        return f"{n} SSRF parameter(s)." if n else "No SSRF callback."

    @staticmethod
    def _with_param(p, existing: dict, name: str, value: str) -> str:
        q = dict(existing)
        q[name] = value
        return urlunparse(p._replace(query=urlencode(q)))

    def _start_listener(self):
        try:
            # fresh hit set per run so a prior run's tokens don't leak in
            _Collector.hits = set()
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _Collector)
            srv.timeout = 1
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            return srv, port
        except OSError:
            return None, 0

    @staticmethod
    def _stop_listener(server, token_param: dict) -> None:
        try:
            server.shutdown()
            server.server_close()
        except Exception:  # noqa: BLE001
            pass
        # clear only this run's tokens
        _Collector.hits -= set(token_param)
