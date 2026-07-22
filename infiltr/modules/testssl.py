"""testssl.sh wrapper — deep TLS/SSL vulnerability audit (JSON output)."""
from __future__ import annotations

import json
import os
import tempfile

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL
from ..utils import host_port

_SEV = {
    "INFO": SEV_INFO, "OK": SEV_INFO, "LOW": SEV_LOW, "MEDIUM": SEV_MEDIUM,
    "HIGH": SEV_HIGH, "CRITICAL": SEV_CRITICAL, "WARN": SEV_LOW,
}


class TestsslWrapper(BaseWrapper):
    MODULE_NAME = "testssl"
    CATEGORY = "web"
    TOOL_BIN = "testssl.sh"
    DESCRIPTION = "Deep TLS/SSL vulnerability + config audit"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 900

    def build_command(self, target: str) -> list[str]:
        host, port = host_port(target)
        self._outfile = tempfile.NamedTemporaryFile(
            prefix="infiltr_testssl_", suffix=".json", delete=False
        ).name
        return [
            self.TOOL_BIN, "--quiet", "--color", "0",
            "--jsonfile", self._outfile,
            f"{host}:{port or 443}",
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        path = getattr(self, "_outfile", None)
        if not path or not os.path.exists(path):
            return findings
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return findings
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        rows = data if isinstance(data, list) else data.get("scanResult", [])
        for row in rows:
            sev = _SEV.get(str(row.get("severity", "INFO")).upper(), SEV_INFO)
            # only surface things that matter
            if sev in (SEV_INFO,) and str(row.get("severity", "")).upper() not in ("WARN",):
                continue
            findings.append(
                Finding(
                    type="tls",
                    name=row.get("id", "tls"),
                    value=str(row.get("finding", ""))[:200],
                    detail=str(row.get("cve", "") or row.get("finding", "")),
                    severity=sev,
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} notable TLS finding(s)."
