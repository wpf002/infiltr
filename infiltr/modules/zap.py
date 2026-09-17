"""OWASP ZAP wrapper — active web-application scanner driven via the ZAP daemon API.

Kali ships only the ZAP daemon (no zap-baseline script), so this module launches
`zaproxy -daemon` on a local port, spiders the target, runs passive rules (and the
active scanner in mode=full), collects alerts, then shuts the daemon down.

mode: "baseline" (spider + passive, tier-1) | "full" (+ active scan, tier-2).
Honors auth_headers (injected via a ZAP replacer rule) for authenticated scans.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
import urllib.parse

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH
from ..utils import base_url
from ..webutil import fetch

_RISK = {"Informational": SEV_INFO, "Low": SEV_LOW, "Medium": SEV_MEDIUM, "High": SEV_HIGH}


def parse_alerts(alerts: list) -> list[Finding]:
    """Map ZAP alerts (JSON) -> Findings. Deduped by (name, param)."""
    findings: list[Finding] = []
    seen: set = set()
    for a in alerts or []:
        name = a.get("alert") or a.get("name") or "ZAP alert"
        param = a.get("param", "")
        key = (name, param, a.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        sev = _RISK.get(a.get("risk", "Informational"), SEV_INFO)
        findings.append(Finding(
            type="zap_alert", name=name, value=a.get("url", "")[:200],
            detail=f"{a.get('risk','')}/{a.get('confidence','')} conf"
                   + (f" param={param}" if param else "")
                   + (f" CWE-{a['cweid']}" if a.get("cweid") not in (None, "", "-1") else ""),
            severity=sev,
            metadata={"cwe": a.get("cweid"), "wasc": a.get("wascid"),
                      "param": param, "evidence": a.get("evidence", ""), "url": a.get("url", "")}))
    return findings


class ZapWrapper(NativeWrapper):
    MODULE_NAME = "zap"
    CATEGORY = "web"
    TOOL_BIN = "zaproxy"
    DESCRIPTION = "OWASP ZAP active web-app scan (spider + passive/active rules)"
    VERSION = "1.0"
    OPTIONS_SCHEMA = {
        "mode": {"type": "string", "default": "baseline", "help": "'baseline' (passive) | 'full' (active)"},
    }
    DEFAULT_TIMEOUT = 900

    @classmethod
    def is_installed(cls) -> bool:
        return shutil.which(cls.TOOL_BIN) is not None

    def _api(self, port: int, path: str, **params) -> dict:
        params["apikey"] = self._key
        url = f"http://127.0.0.1:{port}/JSON/{path}/?{urllib.parse.urlencode(params)}"
        r = fetch(url, timeout=30)
        try:
            return json.loads(r["body"]) if r["body"] else {}
        except json.JSONDecodeError:
            return {}

    def collect(self, target: str) -> list[Finding]:
        import secrets as _secrets
        url = base_url(target)
        mode = str(self.options.get("mode", "baseline")).lower()
        deadline = time.monotonic() + int(self.options.get("timeout", 900))
        self._key = _secrets.token_hex(12)
        port = _free_port()

        proc = subprocess.Popen(
            [self.TOOL_BIN, "-daemon", "-host", "127.0.0.1", "-port", str(port),
             "-config", f"api.key={self._key}",
             "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self._proc = proc
        try:
            if not self._wait_up(port, deadline):
                return [Finding(type="note", name="zap unavailable", value="daemon did not start", severity=SEV_INFO)]

            # authenticated scan: add each auth header to every request via a replacer rule
            for k, v in (self.options.get("auth_headers") or {}).items():
                self._api(port, "replacer/action/addRule", description=f"auth-{k}", enabled="true",
                          matchType="REQ_HEADER", matchString=k, matchRegex="false", replacement=v)

            self._api(port, "core/action/accessUrl", url=url)
            sid = self._api(port, "spider/action/scan", url=url, maxChildren="20").get("scan")
            self._poll(port, "spider/view/status", sid, deadline)
            time.sleep(2)  # let passive scan drain

            if mode == "full":
                asid = self._api(port, "ascan/action/scan", url=url, recurse="true").get("scan")
                self._poll(port, "ascan/view/status", asid, deadline)
                time.sleep(2)

            alerts = self._api(port, "core/view/alerts", baseurl=url).get("alerts", [])
            return parse_alerts(alerts)
        finally:
            self._shutdown(proc)

    def _wait_up(self, port: int, deadline: float) -> bool:
        while time.monotonic() < deadline:
            if self._cancelled:
                return False
            r = fetch(f"http://127.0.0.1:{port}/JSON/core/view/version/?apikey={self._key}", timeout=5)
            if r["status"] == 200:
                return True
            time.sleep(2)
        return False

    def _poll(self, port: int, view: str, scan_id, deadline: float) -> None:
        if scan_id is None:
            return
        while time.monotonic() < deadline and not self._cancelled:
            status = self._api(port, view, scanId=scan_id).get("status", "100")
            if str(status) == "100":
                return
            time.sleep(3)

    def _shutdown(self, proc) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        self._proc = None

    def summarize(self, findings: list[Finding]) -> str:
        real = [f for f in findings if f.type == "zap_alert"]
        return f"{len(real)} ZAP alert(s)." if real else "No ZAP alerts."


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p
