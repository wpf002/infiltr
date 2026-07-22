"""Nuclei wrapper — templated vulnerability/CVE scanning (ProjectDiscovery)."""
from __future__ import annotations

import json
import os
import re
import tempfile

from ..base import (
    BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
)
from ..utils import base_url


def _system_resolver() -> str | None:
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                m = re.match(r"\s*nameserver\s+(\S+)", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None

_SEV_MAP = {
    "info": SEV_INFO, "low": SEV_LOW, "medium": SEV_MEDIUM,
    "high": SEV_HIGH, "critical": SEV_CRITICAL, "unknown": SEV_INFO,
}


class NucleiWrapper(BaseWrapper):
    MODULE_NAME = "nuclei"
    CATEGORY = "web"
    TOOL_BIN = "nuclei"
    DESCRIPTION = "Templated vulnerability / CVE / misconfig scanner"
    VERSION = "1.0"
    OPTIONS_SCHEMA = {
        "severity": {"type": "string", "default": "low,medium,high,critical",
                     "help": "comma severities to report (info,low,medium,high,critical)"},
        "tags": {"type": "string", "default": "", "help": "restrict to template tags (e.g. cve,exposure)"},
        "rate_limit": {"type": "int", "default": 150, "help": "requests/sec"},
    }
    DEFAULT_TIMEOUT = 900

    def build_command(self, target: str) -> list[str]:
        url = base_url(target)
        cmd = [
            self.TOOL_BIN, "-u", url,
            "-jsonl", "-silent", "-no-color",
            "-severity", str(self.options.get("severity", "info,low,medium,high,critical")),
            "-rate-limit", str(self.options.get("rate_limit", 150)),
            "-disable-update-check",
            "-no-mhe",  # don't abort the whole host after N template errors (404s trip it)
        ]
        tags = self.options.get("tags")
        if tags:
            cmd += ["-tags", str(tags)]
        # give nuclei's Go resolver the system nameserver (needs a file, ip:53) so
        # it can resolve internal hostnames too; harmless for public targets
        resolver = self.options.get("resolver") or _system_resolver()
        if resolver:
            self._resolver_file = tempfile.NamedTemporaryFile(
                prefix="infiltr_nuclei_r_", suffix=".txt", delete=False, mode="w"
            )
            self._resolver_file.write(f"{resolver}:53\n")
            self._resolver_file.close()
            cmd += ["-r", self._resolver_file.name]
        return cmd

    def _cleanup(self):
        rf = getattr(self, "_resolver_file", None)
        if rf is not None:
            try:
                os.unlink(rf.name)
            except OSError:
                pass

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        self._cleanup()
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), SEV_INFO)
            findings.append(
                Finding(
                    type="vuln",
                    name=info.get("name") or obj.get("template-id", "nuclei"),
                    value=obj.get("matched-at") or obj.get("host", ""),
                    detail=f"{obj.get('template-id','')} — {', '.join(info.get('tags', []) or [])}",
                    severity=sev,
                    metadata={
                        "template_id": obj.get("template-id"),
                        "type": obj.get("type"),
                        "matched_at": obj.get("matched-at"),
                    },
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} template hit(s)." if findings else "No template matches."
