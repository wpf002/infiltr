"""subfinder wrapper — passive subdomain enumeration (ProjectDiscovery)."""
from __future__ import annotations

from ..base import BaseWrapper, Finding, SEV_INFO
from ..utils import hostname


class SubfinderWrapper(BaseWrapper):
    MODULE_NAME = "subfinder"
    CATEGORY = "recon"
    TOOL_BIN = "subfinder"
    DESCRIPTION = "Passive subdomain enumeration"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        return [self.TOOL_BIN, "-d", hostname(target), "-silent", "-no-color"]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            host = line.strip()
            if host and "." in host and host not in seen and " " not in host:
                seen.add(host)
                findings.append(Finding(type="subdomain", name="host", value=host, severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} subdomain(s)."
