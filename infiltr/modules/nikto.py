"""Nikto wrapper — web server misconfiguration scanner."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH
from ..utils import base_url, strip_ansi

_OSVDB_RE = re.compile(r"(OSVDB-\d+|CVE-\d{4}-\d+)", re.I)

# heuristic severity keywords
_HIGH_KW = ("sql", "rce", "remote code", "command execution", "shell", "traversal", "lfi", "rfi")
_MED_KW = ("xss", "csrf", "injection", "default", "backup", "admin", "phpmyadmin", "outdated", "unpatched")


class NiktoWrapper(BaseWrapper):
    MODULE_NAME = "nikto"
    CATEGORY = "web"
    TOOL_BIN = "nikto"
    DESCRIPTION = "Web server / CGI vulnerability scanner"
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        url = base_url(target)
        cmd = [self.TOOL_BIN, "-h", url, "-ask", "no", "-nointeractive"]
        tuning = self.options.get("tuning")
        if tuning:
            cmd += ["-Tuning", str(tuning)]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            msg = line.lstrip("+ ").strip()
            if not msg or msg.lower().startswith(("target ", "start time", "end time", "host", "server:", "ssl info")):
                # keep Server: as info
                if msg.lower().startswith("server:"):
                    findings.append(Finding(type="header", name="Server", value=msg[7:].strip(), severity=SEV_INFO))
                continue
            low = msg.lower()
            if any(k in low for k in _HIGH_KW):
                sev = SEV_HIGH
            elif any(k in low for k in _MED_KW):
                sev = SEV_MEDIUM
            else:
                sev = SEV_LOW
            ref = _OSVDB_RE.search(msg)
            findings.append(
                Finding(
                    type="finding",
                    name=ref.group(1) if ref else "nikto",
                    value=msg[:200],
                    detail=msg,
                    severity=sev,
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        real = [f for f in findings if f.type == "finding"]
        return f"{len(real)} finding(s)."
