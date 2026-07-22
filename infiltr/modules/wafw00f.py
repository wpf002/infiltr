"""wafw00f wrapper — Web Application Firewall detection."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW
from ..utils import base_url, strip_ansi

_BEHIND_RE = re.compile(r"is behind\s+(.+?)(?:\s+WAF| WAF|\.|$)", re.I)


class Wafw00fWrapper(BaseWrapper):
    MODULE_NAME = "wafw00f"
    CATEGORY = "recon"
    TOOL_BIN = "wafw00f"
    DESCRIPTION = "Web Application Firewall detection"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 120

    def build_command(self, target: str) -> list[str]:
        return [self.TOOL_BIN, "-a", base_url(target)]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for line in text.splitlines():
            m = _BEHIND_RE.search(line)
            if m:
                waf = m.group(1).strip().strip("()")
                findings.append(
                    Finding(type="waf", name="WAF", value=waf,
                            detail="target is behind a WAF", severity=SEV_LOW)
                )
        if not findings and re.search(r"No WAF detected", text, re.I):
            findings.append(Finding(type="waf", name="WAF", value="none detected", severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        wafs = [f for f in findings if f.value != "none detected"]
        return f"{len(wafs)} WAF(s) detected." if wafs else "No WAF detected."
