"""Nuclei wrapper — templated vulnerability/CVE scanning (ProjectDiscovery)."""
from __future__ import annotations

import json

from ..base import (
    BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
)
from ..utils import base_url

_SEV_MAP = {
    "info": SEV_INFO, "low": SEV_LOW, "medium": SEV_MEDIUM,
    "high": SEV_HIGH, "critical": SEV_CRITICAL, "unknown": SEV_INFO,
}


class NucleiWrapper(BaseWrapper):
    MODULE_NAME = "nuclei"
    CATEGORY = "web"
    TOOL_BIN = "nuclei"
    DESCRIPTION = "Templated vulnerability / CVE / misconfig scanner"
    VERSION = "1.0"
    OPTIONS_SCHEMA = {
        "severity": {"type": "string", "default": "low,medium,high,critical",
                     "help": "comma severities to report (info,low,medium,high,critical)"},
        "tags": {"type": "string", "default": "", "help": "restrict to template tags (e.g. cve,exposure)"},
        "rate_limit": {"type": "int", "default": 150, "help": "requests/sec"},
    }
    DEFAULT_TIMEOUT = 900

    def build_command(self, target: str) -> list[str]:
        url = base_url(target)
        cmd = [
            self.TOOL_BIN, "-u", url,
            "-jsonl", "-silent", "-no-color",
            "-severity", str(self.options.get("severity", "low,medium,high,critical")),
            "-rate-limit", str(self.options.get("rate_limit", 150)),
            "-disable-update-check",
        ]
        tags = self.options.get("tags")
        if tags:
            cmd += ["-tags", str(tags)]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), SEV_INFO)
            findings.append(
                Finding(
                    type="vuln",
                    name=info.get("name") or obj.get("template-id", "nuclei"),
                    value=obj.get("matched-at") or obj.get("host", ""),
                    detail=f"{obj.get('template-id','')} — {', '.join(info.get('tags', []) or [])}",
                    severity=sev,
                    metadata={
                        "template_id": obj.get("template-id"),
                        "type": obj.get("type"),
                        "matched_at": obj.get("matched-at"),
                    },
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} template hit(s)." if findings else "No template matches."
