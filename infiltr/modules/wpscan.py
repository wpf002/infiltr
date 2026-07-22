"""WPScan wrapper — WordPress enumeration + vulnerability checks."""
from __future__ import annotations

import json

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH
from ..utils import base_url


class WpscanWrapper(BaseWrapper):
    MODULE_NAME = "wpscan"
    CATEGORY = "web"
    TOOL_BIN = "wpscan"
    DESCRIPTION = "WordPress version / plugin / user / vuln enumeration"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        cmd = [
            self.TOOL_BIN, "--url", base_url(target),
            "--format", "json", "--no-banner",
            "--random-user-agent",
            "--enumerate", "vp,u",
        ]
        token = self.options.get("api_token")
        if token:
            cmd += ["--api-token", str(token)]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = stdout.strip()
        start = text.find("{")
        if start < 0:
            return []
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []

        ver = (data.get("version") or {})
        if ver.get("number"):
            findings.append(Finding(type="wp_version", name="WordPress", value=ver["number"],
                                    severity=SEV_LOW if ver.get("vulnerabilities") else SEV_INFO))
        for v in ver.get("vulnerabilities", []) or []:
            findings.append(Finding(type="vuln", name=v.get("title", "wp-core vuln"), value="core",
                                    severity=SEV_HIGH))

        for name, pl in (data.get("plugins") or {}).items():
            vulns = pl.get("vulnerabilities", []) or []
            findings.append(Finding(type="wp_plugin", name=name, value=(pl.get("version") or {}).get("number", "?"),
                                    detail=f"{len(vulns)} known vuln(s)",
                                    severity=SEV_HIGH if vulns else SEV_INFO))
            for v in vulns:
                findings.append(Finding(type="vuln", name=v.get("title", "plugin vuln"), value=name, severity=SEV_HIGH))

        for user in (data.get("users") or {}):
            findings.append(Finding(type="wp_user", name="user", value=user, severity=SEV_MEDIUM))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        vulns = sum(1 for f in findings if f.type == "vuln")
        return f"{len(findings)} WP finding(s), {vulns} vuln(s)." if findings else "Not WordPress / nothing found."
