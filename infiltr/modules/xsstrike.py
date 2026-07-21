"""XSStrike wrapper — reflected/DOM XSS detection (cloned Python tool)."""
from __future__ import annotations

import os
import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_HIGH
from ..utils import normalize_url, strip_ansi

_PAYLOAD_RE = re.compile(r"payload:\s*(.+)", re.I)


class XSStrikeWrapper(BaseWrapper):
    MODULE_NAME = "xsstrike"
    CATEGORY = "web"
    TOOL_BIN = "python3"          # invoked as `python3 xsstrike.py`
    DESCRIPTION = "Reflected / DOM XSS detection and payload generation"
    DEFAULT_TIMEOUT = 300

    @classmethod
    def is_installed(cls) -> bool:
        import shutil
        from .. import config
        script = config.GLOBAL.get("xsstrike_path", "")
        return shutil.which("python3") is not None and bool(script) and os.path.exists(script)

    def build_command(self, target: str) -> list[str]:
        from .. import config
        script = self.options.get("xsstrike_path") or config.GLOBAL.get("xsstrike_path")
        url = normalize_url(target)
        cmd = ["python3", script, "-u", url, "--skip"]
        if self.options.get("crawl"):
            cmd.append("--crawl")
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for line in text.splitlines():
            low = line.lower()
            if "vulnerable" in low or "reflected" in low or ("payload" in low and "efficiency" in low):
                pm = _PAYLOAD_RE.search(line)
                findings.append(
                    Finding(
                        type="xss",
                        name="reflected XSS",
                        value=(pm.group(1).strip() if pm else line.strip())[:200],
                        detail=line.strip(),
                        severity=SEV_HIGH,
                    )
                )
        # de-dup
        uniq: dict[str, Finding] = {}
        for f in findings:
            uniq[f.value] = f
        return list(uniq.values())

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} XSS vector(s)." if findings else "No XSS found."
