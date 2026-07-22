"""dalfox wrapper — modern XSS scanner."""
from __future__ import annotations

import json

from ..base import BaseWrapper, Finding, SEV_MEDIUM, SEV_HIGH, SEV_INFO
from ..utils import normalize_url

_SEV = {"low": SEV_MEDIUM, "medium": SEV_MEDIUM, "high": SEV_HIGH, "critical": SEV_HIGH}


class DalfoxWrapper(BaseWrapper):
    MODULE_NAME = "dalfox"
    CATEGORY = "web"
    TOOL_BIN = "dalfox"
    DESCRIPTION = "Parameter analysis + XSS scanning"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        return [self.TOOL_BIN, "url", normalize_url(target),
                "--format", "json", "--no-color", "--silence", "--no-spinner"]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        text = stdout.strip()
        objs = []
        # dalfox emits either a JSON array or one JSON object per line
        try:
            data = json.loads(text)
            objs = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        objs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        for o in objs:
            sev = _SEV.get(str(o.get("severity", "high")).lower(), SEV_HIGH)
            findings.append(
                Finding(
                    type="xss",
                    name=o.get("inject_type") or o.get("type") or "XSS",
                    value=(o.get("poc") or o.get("data") or "")[:300],
                    detail=f"param={o.get('param','')} method={o.get('method','')} cwe={o.get('cwe','')}",
                    severity=sev,
                    metadata={"param": o.get("param"), "poc": o.get("poc")},
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} XSS PoC(s)." if findings else "No XSS found."
