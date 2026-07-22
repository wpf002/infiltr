"""httpx wrapper — HTTP probing / fingerprinting (ProjectDiscovery)."""
from __future__ import annotations

import json
import shutil

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import host_port, base_url
from urllib.parse import urlparse

# Kali ships the ProjectDiscovery binary as "httpx-toolkit"; upstream names it "httpx".
_HTTPX_BINS = ("httpx-toolkit", "httpx")


class HttpxWrapper(BaseWrapper):
    MODULE_NAME = "httpx"
    CATEGORY = "recon"
    TOOL_BIN = "httpx-toolkit"
    DESCRIPTION = "HTTP probe: status, title, tech, server, TLS"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 180

    @classmethod
    def is_installed(cls) -> bool:
        return any(shutil.which(b) for b in _HTTPX_BINS)

    def _bin(self) -> str:
        for b in _HTTPX_BINS:
            if shutil.which(b):
                return b
        return self.TOOL_BIN

    def build_command(self, target: str) -> list[str]:
        # target is fed on stdin; httpx reads URLs from stdin with -json output
        return [
            self._bin(),
            "-json", "-silent", "-no-color",
            "-status-code", "-title", "-tech-detect", "-web-server", "-ip",
        ]

    def stdin_for(self, target: str) -> str:
        # httpx wants host:port on stdin (a bare hostname or a scheme'd URL both
        # fail on v1.9.x), so always supply an explicit port from the scheme.
        host, port = host_port(target)
        if not port:
            port = 443 if urlparse(base_url(target)).scheme == "https" else 80
        return f"{host}:{port}\n"

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
