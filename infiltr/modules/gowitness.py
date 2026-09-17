"""gowitness wrapper — headless screenshot of the target for evidence."""
from __future__ import annotations

import glob
import os
import tempfile

from ..base import BaseWrapper, Finding, SEV_INFO
from ..utils import base_url


class GowitnessWrapper(BaseWrapper):
    MODULE_NAME = "gowitness"
    CATEGORY = "recon"
    TOOL_BIN = "gowitness"
    DESCRIPTION = "Headless screenshot of the target (visual evidence)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 120

    def build_command(self, target: str) -> list[str]:
        self._outdir = tempfile.mkdtemp(prefix="infiltr_gowitness_")
        # gowitness 3.x subcommand form; screenshot a single URL into a temp dir
        return [
            self.TOOL_BIN, "scan", "single",
            "-u", base_url(target),
            "--screenshot-path", self._outdir,
            "--timeout", "20",
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        outdir = getattr(self, "_outdir", None)
        shots = sorted(glob.glob(os.path.join(outdir, "*.png"))) if outdir else []
        for shot in shots:
            findings.append(Finding(
                type="screenshot", name="screenshot", value=os.path.basename(shot),
                detail=f"captured render at {shot}", severity=SEV_INFO,
                metadata={"path": shot, "bytes": os.path.getsize(shot) if os.path.exists(shot) else 0}))
        if not shots and ("http" in (stdout + stderr).lower()):
            findings.append(Finding(type="note", name="captured", value="see raw output", severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        shots = [f for f in findings if f.type == "screenshot"]
        return f"{len(shots)} screenshot(s) captured."
