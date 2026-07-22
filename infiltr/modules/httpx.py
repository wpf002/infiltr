"""httpx wrapper — HTTP probing / fingerprinting (ProjectDiscovery)."""
from __future__ import annotations

import json

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import base_url


class HttpxWrapper(BaseWrapper):
    MODULE_NAME = "httpx"
    CATEGORY = "recon"
    TOOL_BIN = "httpx"
    DESCRIPTION = "HTTP probe: status, title, tech, server, TLS"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 180

    def build_command(self, target: str) -> list[str]:
        # target is fed on stdin; httpx reads URLs from stdin with -json output
        return [
            self.TOOL_BIN,
            "-json", "-silent", "-no-color",
            "-status-code", "-title", "-tech-detect", "-web-server", "-ip",
        ]

    def stdin_for(self, target: str) -> str:
        return base_url(target) + "\n"

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
            url = obj.get("url", "")
            status = obj.get("status_code") or obj.get("status-code")
            if status is not None:
                sev = SEV_MEDIUM if status in (401, 403) else SEV_INFO
                findings.append(
                    Finding(type="http", name="status", value=str(status),
                            detail=url, severity=sev, metadata={"url": url})
                )
            if obj.get("title"):
                findings.append(Finding(type="title", name="title", value=obj["title"], severity=SEV_INFO))
            server = obj.get("webserver") or obj.get("web-server")
            if server:
                findings.append(Finding(type="header", name="Server", value=server, severity=SEV_LOW))
            for tech in obj.get("tech") or obj.get("technologies") or []:
                findings.append(Finding(type="technology", name=tech, value="", severity=SEV_LOW))
            for ip in obj.get("a") or ([obj["ip"]] if obj.get("ip") else []):
                findings.append(Finding(type="ip", name="ip", value=ip, severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        techs = sum(1 for f in findings if f.type == "technology")
        return f"probed: {techs} tech, {len(findings)} datapoint(s)."
