"""Naabu wrapper — fast connect-based port scan (ProjectDiscovery).

Uses TCP connect (-scan-type c) so it works unprivileged / in a container without
CAP_NET_RAW, unlike masscan."""
from __future__ import annotations

import json

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import hostname

_DB_PORTS = {3306, 5432, 1433, 27017, 6379, 9200, 5984, 11211}


class NaabuWrapper(BaseWrapper):
    MODULE_NAME = "naabu"
    CATEGORY = "recon"
    TOOL_BIN = "naabu"
    DESCRIPTION = "Fast TCP-connect port scan (unprivileged, no raw sockets)"
    VERSION = "1.0"
    OPTIONS_SCHEMA = {
        "ports": {"type": "string", "default": "top-1000", "help": "'top-1000' | range | csv"},
        "rate": {"type": "int", "default": 500, "help": "packets/sec"},
    }
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        cmd = [
            self.TOOL_BIN, "-host", hostname(target),
            "-json", "-silent", "-no-color",
            "-scan-type", "c",                 # TCP connect (unprivileged)
            "-rate", str(int(self.options.get("rate", 500))),
        ]
        ports = str(self.options.get("ports", "top-1000"))
        if ports == "top-1000":
            cmd += ["-top-ports", "1000"]
        else:
            cmd += ["-p", ports]
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
            port = obj.get("port")
            if not port:
                continue
            sev = SEV_MEDIUM if int(port) in _DB_PORTS else SEV_LOW
            findings.append(Finding(
                type="open_port", name=f"{port}/tcp", value="open",
                detail=obj.get("host", ""), severity=sev,
                metadata={"port": int(port), "ip": obj.get("ip", ""), "host": obj.get("host", "")}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} open port(s)."
