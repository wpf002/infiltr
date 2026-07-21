"""Gobuster wrapper — directory/file brute force."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import base_url, strip_ansi

# "/admin                (Status: 301) [Size: 234] [--> /admin/]"
_LINE_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d{3})\)", re.M)


class GobusterWrapper(BaseWrapper):
    MODULE_NAME = "gobuster"
    CATEGORY = "web"
    TOOL_BIN = "gobuster"
    DESCRIPTION = "Directory/file brute forcing"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        url = base_url(target)
        return [
            self.TOOL_BIN, "dir",
            "-u", url,
            "-w", str(self.options.get("wordlist")),
            "-t", str(self.options.get("threads", 30)),
            "-s", str(self.options.get("status_codes", "200,204,301,302,307,401,403")),
            "-b", "",
            "-q",
            "--no-error",
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for path, code in _LINE_RE.findall(text):
            status = int(code)
            sev = SEV_MEDIUM if status in (401, 403) else (
                SEV_LOW if status in (200, 301, 302) else SEV_INFO
            )
            findings.append(
                Finding(
                    type="path",
                    name=path,
                    value=str(status),
                    detail=f"HTTP {status}",
                    severity=sev,
                    metadata={"status": status},
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} path(s) discovered."
