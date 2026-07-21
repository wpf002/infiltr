"""Hydra wrapper — network login brute force."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_CRITICAL
from ..utils import host_port, strip_ansi, base_url
from urllib.parse import urlparse

# "[80][http-get] host: 127.0.0.1   login: admin   password: password"
_CRED_RE = re.compile(
    r"\[\d+\]\[[^\]]+\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S*)", re.I
)


class HydraWrapper(BaseWrapper):
    MODULE_NAME = "hydra"
    CATEGORY = "auth"
    TOOL_BIN = "hydra"
    DESCRIPTION = "Parallel network login brute forcer"
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        host, port = host_port(target)
        service = self.options.get("service", "http-get")
        path = urlparse(base_url(target) + "/").path or "/"
        # allow explicit form spec via options
        cmd = [
            self.TOOL_BIN,
            "-L", str(self.options.get("userlist")),
            "-P", str(self.options.get("passlist")),
            "-t", str(self.options.get("threads", 8)),
            "-f",              # stop after first valid pair per host (override w/ opt)
        ]
        if self.options.get("find_all"):
            cmd.remove("-f")
        if port:
            cmd += ["-s", str(port)]
        cmd.append(host)
        # service module + optional path
        if service in {"http-get", "http-head", "https-get"}:
            cmd += [service, str(self.options.get("path", path))]
        else:
            cmd.append(service)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for host, login, password in _CRED_RE.findall(text):
            findings.append(
                Finding(
                    type="credential",
                    name=f"{login}:{password}",
                    value=host,
                    detail=f"valid login {login} / {password}",
                    severity=SEV_CRITICAL,
                    metadata={"login": login, "password": password, "host": host},
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} valid credential pair(s)." if findings else "No valid credentials found."
