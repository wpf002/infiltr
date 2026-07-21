"""Core abstractions every tool wrapper builds on."""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .utils import truncate

# Status vocabulary
PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
SKIPPED = "SKIPPED"

# Severity vocabulary (populated from Phase 5 onward; deterministic engine owns it)
SEV_INFO = "info"
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"
SEV_CRITICAL = "critical"
SEVERITY_ORDER = [SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL]


def severity_rank(sev: str | None) -> int:
    try:
        return SEVERITY_ORDER.index(sev or SEV_INFO)
    except ValueError:
        return 0


@dataclass
class Finding:
    """A single normalized observation produced by a wrapper."""
    type: str                      # e.g. "open_port", "header", "vuln", "path"
    name: str                      # short label
    value: str = ""                # primary value
    detail: str = ""               # extra context
    severity: str = SEV_INFO       # deterministic engine assigns/overrides this
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    module: str
    category: str
    target: str
    status: str = PASS
    command: str = ""
    returncode: int | None = None
    raw_output: str = ""
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    severity: str = SEV_INFO          # highest severity among findings
    duration: float = 0.0
    error: str | None = None
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    def compute_severity(self) -> str:
        """Roll up the highest finding severity onto the result."""
        top = SEV_INFO
        for f in self.findings:
            if severity_rank(f.severity) > severity_rank(top):
                top = f.severity
        self.severity = top
        return top


class BaseWrapper:
    """Subclass per tool. Override MODULE_NAME/CATEGORY/TOOL_BIN, build_command, parse_output."""

    MODULE_NAME: str = "base"
    CATEGORY: str = "misc"          # recon | web | auth | misc
    TOOL_BIN: str = ""              # binary checked with shutil.which
    DESCRIPTION: str = ""
    DEFAULT_TIMEOUT: int = 300

    def __init__(self, options: dict[str, Any] | None = None):
        self.options = options or {}

    # ---- discovery / availability -------------------------------------
    @classmethod
    def is_installed(cls) -> bool:
        if not cls.TOOL_BIN:
            return False
        return shutil.which(cls.TOOL_BIN) is not None

    def tool_path(self) -> str | None:
        return shutil.which(self.TOOL_BIN) if self.TOOL_BIN else None

    # ---- to override --------------------------------------------------
    def build_command(self, target: str) -> list[str]:
        raise NotImplementedError

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        """Return findings extracted from raw tool output. Override per tool."""
        return []

    def summarize(self, findings: list[Finding]) -> str:
        if not findings:
            return "No findings."
        return f"{len(findings)} finding(s)."

    # ---- execution ----------------------------------------------------
    def run(self, target: str) -> ScanResult:
        started = datetime.now(timezone.utc)
        result = ScanResult(
            module=self.MODULE_NAME,
            category=self.CATEGORY,
            target=target,
            started_at=started.isoformat(),
        )

        if not self.is_installed():
            result.status = ERROR
            result.error = f"{self.TOOL_BIN} not installed (not on PATH)"
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        try:
            cmd = self.build_command(target)
        except Exception as exc:  # noqa: BLE001
            result.status = ERROR
            result.error = f"build_command failed: {exc}"
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        result.command = " ".join(cmd)
        timeout = int(self.options.get("timeout", self.DEFAULT_TIMEOUT))
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            result.status = ERROR
            result.error = f"timed out after {timeout}s"
            result.raw_output = truncate((exc.stdout or "") if isinstance(exc.stdout, str) else "")
            result.duration = round(time.monotonic() - t0, 2)
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result
        except FileNotFoundError:
            result.status = ERROR
            result.error = f"{self.TOOL_BIN} vanished from PATH mid-run"
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result
        except Exception as exc:  # noqa: BLE001
            result.status = ERROR
            result.error = f"execution failed: {exc}"
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        result.duration = round(time.monotonic() - t0, 2)
        result.returncode = rc
        result.raw_output = truncate((stdout or "") + (("\n[stderr]\n" + stderr) if stderr else ""))

        try:
            findings = self.parse_output(stdout or "", stderr or "", rc)
        except Exception as exc:  # noqa: BLE001
            result.status = FAIL
            result.error = f"parse_output failed: {exc}"
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        result.findings = findings
        result.summary = self.summarize(findings)
        result.compute_severity()
        result.status = PASS
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result
