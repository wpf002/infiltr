"""dnsx wrapper — DNS record resolution (ProjectDiscovery)."""
from __future__ import annotations

import json

from ..base import BaseWrapper, Finding, SEV_INFO
from ..utils import hostname


class DnsxWrapper(BaseWrapper):
    MODULE_NAME = "dnsx"
    CATEGORY = "recon"
    TOOL_BIN = "dnsx"
    DESCRIPTION = "DNS resolver: A / AAAA / CNAME / records"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 120

    def build_command(self, target: str) -> list[str]:
        # host is fed on stdin; emit JSON with the resolved records
        return [self.TOOL_BIN, "-json", "-silent", "-a", "-aaaa", "-cname", "-resp"]

    def stdin_for(self, target: str) -> str:
        return hostname(target) + "\n"

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
            host = obj.get("host", "")
            for a in obj.get("a", []) or []:
                findings.append(Finding(type="dns_a", name=host or "A", value=a, severity=SEV_INFO))
            for a in obj.get("aaaa", []) or []:
                findings.append(Finding(type="dns_aaaa", name=host or "AAAA", value=a, severity=SEV_INFO))
            for c in obj.get("cname", []) or []:
                findings.append(Finding(type="dns_cname", name=host or "CNAME", value=c, severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} DNS record(s)."
