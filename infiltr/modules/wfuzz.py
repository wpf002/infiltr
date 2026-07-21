"""wfuzz wrapper — web content/parameter fuzzing."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import base_url, strip_ansi

# "000000012:   C=200      7 L      12 W      145 Ch      "admin""
_LINE_RE = re.compile(
    r"C=(\d{3})\s+.*?Ch\s+\"?(.*?)\"?\s*$", re.M
)


class WfuzzWrapper(BaseWrapper):
    MODULE_NAME = "wfuzz"
    CATEGORY = "web"
    TOOL_BIN = "wfuzz"
    DESCRIPTION = "Web application fuzzer"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        url = base_url(target).rstrip("/") + "/FUZZ"
        return [
            self.TOOL_BIN,
            "-c",
            "-w", str(self.options.get("wordlist")),
            "-t", str(self.options.get("threads", 30)),
            "--hc", str(self.options.get("hide_codes", "404")),
            url,
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        seen: set[str] = set()
        for code, payload in _LINE_RE.findall(text):
            payload = payload.strip().strip('"')
            key = f"{code}:{payload}"
            if key in seen or not payload:
                continue
            seen.add(key)
            status = int(code)
            sev = SEV_MEDIUM if status in (401, 403) else (
                SEV_LOW if status in (200, 301, 302) else SEV_INFO
            )
            findings.append(
                Finding(
                    type="path",
                    name=payload,
                    value=str(status),
                    detail=f"HTTP {status}",
                    severity=sev,
                    metadata={"status": status},
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} response(s) matched."
