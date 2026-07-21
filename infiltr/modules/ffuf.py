"""ffuf wrapper — fast web fuzzing (JSON output to a temp file)."""
from __future__ import annotations

import json
import os
import tempfile

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import base_url


class FfufWrapper(BaseWrapper):
    MODULE_NAME = "ffuf"
    CATEGORY = "web"
    TOOL_BIN = "ffuf"
    DESCRIPTION = "Fast web fuzzer for content/parameter discovery"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        url = base_url(target).rstrip("/") + "/FUZZ"
        self._outfile = tempfile.NamedTemporaryFile(
            prefix="infiltr_ffuf_", suffix=".json", delete=False
        ).name
        return [
            self.TOOL_BIN,
            "-u", url,
            "-w", str(self.options.get("wordlist")),
            "-t", str(self.options.get("threads", 40)),
            "-mc", str(self.options.get("match_codes", "200,204,301,302,307,401,403,405")),
            "-of", "json",
            "-o", self._outfile,
            "-s",
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        path = getattr(self, "_outfile", None)
        if not path or not os.path.exists(path):
            return findings
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return findings
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        for r in data.get("results", []):
            status = int(r.get("status", 0))
            url = r.get("url", "")
            sev = SEV_MEDIUM if status in (401, 403) else (
                SEV_LOW if status in (200, 301, 302) else SEV_INFO
            )
            findings.append(
                Finding(
                    type="path",
                    name=url,
                    value=str(status),
                    detail=f"{r.get('length', 0)} bytes",
                    severity=sev,
                    metadata={"status": status, "length": r.get("length")},
                )
            )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} hit(s)."
