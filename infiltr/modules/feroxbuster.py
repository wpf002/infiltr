"""Feroxbuster wrapper — recursive content discovery."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import base_url, strip_ansi

_LINE_RE = re.compile(r"^\s*(\d{3})\s+\w+\s+.*?(https?://\S+)", re.M)


class FeroxbusterWrapper(BaseWrapper):
    MODULE_NAME = "feroxbuster"
    CATEGORY = "web"
    TOOL_BIN = "feroxbuster"
    DESCRIPTION = "Recursive directory / file brute force"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        url = base_url(target)
        codes = self.options.get("status_codes", [200, 301, 302, 401, 403])
        cmd = [
            self.TOOL_BIN,
            "-u", url,
            "-w", str(self.options.get("wordlist")),
            "-t", str(self.options.get("threads", 25)),
            "-d", str(self.options.get("depth", 2)),
            "--no-state",
            "-q",
        ]
        if codes:
            cmd += ["-s", ",".join(str(c) for c in codes)]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        seen: set[str] = set()
        for code, url in _LINE_RE.findall(text):
            if url in seen:
                continue
            seen.add(url)
            findings.append(_path_finding(int(code), url))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} path(s) discovered."


def _path_finding(code: int, url: str) -> Finding:
    if code in (401, 403):
        sev = SEV_MEDIUM
    elif code in (200, 301, 302):
        sev = SEV_LOW
    else:
        sev = SEV_INFO
    return Finding(
        type="path",
        name=url,
        value=str(code),
        detail=f"HTTP {code}",
        severity=sev,
        metadata={"status": code},
    )
