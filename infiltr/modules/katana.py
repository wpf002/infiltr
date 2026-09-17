"""Katana wrapper — web crawler for endpoint/asset discovery (ProjectDiscovery)."""
from __future__ import annotations

import json

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW
from ..utils import base_url, hostname


class KatanaWrapper(BaseWrapper):
    MODULE_NAME = "katana"
    CATEGORY = "recon"
    TOOL_BIN = "katana"
    DESCRIPTION = "Crawl the target for endpoints, URLs, and parameters"
    VERSION = "1.0"
    HEADER_FLAG = "-H"
    OPTIONS_SCHEMA = {
        "depth": {"type": "int", "default": 2, "help": "crawl depth"},
        "js_crawl": {"type": "bool", "default": True, "help": "parse JS for endpoints"},
    }
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        cmd = [
            self.TOOL_BIN, "-u", base_url(target),
            "-jsonl", "-silent", "-no-color",
            "-depth", str(int(self.options.get("depth", 2))),
            "-timeout", "10",
            "-c", "10",
            "-fs", "rdn",   # stay on the same root domain (no scope expansion)
        ]
        if self.options.get("js_crawl", True):
            cmd.append("-jc")
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        host = hostname(base_url(self.options.get("_target", "")))  # optional
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("endpoint") or (obj.get("request") or {}).get("endpoint") or obj.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            has_param = "?" in url
            findings.append(Finding(
                type="endpoint", name=url, value="param" if has_param else "path",
                detail="crawled endpoint" + (" with parameters" if has_param else ""),
                severity=SEV_LOW if has_param else SEV_INFO,
                metadata={"url": url}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        params = sum(1 for f in findings if f.value == "param")
        return f"{len(findings)} endpoint(s) crawled, {params} with parameters."
