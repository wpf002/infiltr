"""XSStrike wrapper — reflected/DOM XSS detection (cloned Python tool)."""
from __future__ import annotations

import os
import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_HIGH
from ..utils import normalize_url, strip_ansi

_PAYLOAD_RE = re.compile(r"payload:\s*(.+)", re.I)
_EFF_RE = re.compile(r"efficiency:\s*(\d+)", re.I)
_CONF_RE = re.compile(r"confidence:\s*(\d+)", re.I)
_CONTEXT_RE = re.compile(r"context:\s*(\w+)", re.I)


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
        lines = text.splitlines()
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            pm = _PAYLOAD_RE.search(line)
            if not pm:
                continue
            payload = pm.group(1).strip()
            if not payload:
                continue
            # look at a small window around the payload for context/scores
            window = "\n".join(lines[max(0, i - 2): i + 4])
            eff = _EFF_RE.search(window)
            conf = _CONF_RE.search(window)
            ctx = _CONTEXT_RE.search(window)
            context = ctx.group(1).lower() if ctx else _infer_context(payload)
            ptype = "DOM" if "dom" in window.lower() else "reflected"

            findings.append(
                Finding(
                    type="xss",
                    name=f"{ptype} XSS ({context})",
                    value=payload[:200],
                    detail=(f"context={context}"
                            + (f" efficiency={eff.group(1)}%" if eff else "")
                            + (f" confidence={conf.group(1)}" if conf else "")),
                    severity=SEV_HIGH,
                    metadata={
                        "payload_type": ptype,
                        "context": context,
                        "efficiency": int(eff.group(1)) if eff else None,
                        "confidence": int(conf.group(1)) if conf else None,
                    },
                )
            )

        # fallback: explicit "vulnerable" markers with no payload line
        if not findings:
            for line in lines:
                if "vulnerable" in line.lower():
                    findings.append(
                        Finding(type="xss", name="reflected XSS", value=line.strip()[:200],
                                detail=line.strip(), severity=SEV_HIGH)
                    )

        uniq: dict[str, Finding] = {}
        for f in findings:
            uniq[f.value] = f
        return list(uniq.values())

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} XSS vector(s)." if findings else "No XSS found."


def _infer_context(payload: str) -> str:
    p = payload.lower()
    if "<script" in p or "</script" in p:
        return "script"
    if "onerror" in p or "onload" in p or "javascript:" in p:
        return "attribute"
    if p.startswith("<"):
        return "html"
    return "unknown"
