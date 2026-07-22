"""masscan wrapper — fast asynchronous port scanner (needs CAP_NET_RAW)."""
from __future__ import annotations

import re
import socket

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW
from ..utils import hostname

_OPEN_RE = re.compile(r"^open\s+(tcp|udp)\s+(\d+)\s+(\S+)", re.M)


class MasscanWrapper(BaseWrapper):
    MODULE_NAME = "masscan"
    CATEGORY = "recon"
    TOOL_BIN = "masscan"
    DESCRIPTION = "Fast wide-range port sweep (raw sockets)"
    VERSION = "1.0"
    OPTIONS_SCHEMA = {
        "ports": {"type": "string", "default": "1-1000", "help": "port range/list"},
        "rate": {"type": "int", "default": 1000, "help": "packets/sec"},
    }
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        host = hostname(target)
        try:
            ip = socket.gethostbyname(host)   # masscan needs an IP, not a hostname
        except OSError:
            ip = host
        return [
            self.TOOL_BIN, ip,
            "-p", str(self.options.get("ports", "1-1000")),
            "--rate", str(self.options.get("rate", 1000)),
            "-oL", "-",
            "--wait", "2",
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        for proto, port, ip in _OPEN_RE.findall(stdout):
            findings.append(
                Finding(type="open_port", name=f"{port}/{proto}", value="open",
                        detail=ip, severity=SEV_LOW, metadata={"port": int(port), "protocol": proto, "ip": ip})
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} open port(s)."
