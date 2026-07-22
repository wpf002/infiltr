"""Core abstractions every tool wrapper builds on."""
from __future__ import annotations

import os
import shutil
import signal
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
    VERSION: str = "1.0"
    OPTIONS_SCHEMA: dict[str, Any] = {}   # {option: {"type","default","help"}}
    DEFAULT_TIMEOUT: int = 300

    def __init__(self, options: dict[str, Any] | None = None):
        self.options = options or {}
        self._proc: subprocess.Popen | None = None
        self._cancelled = False

    # ---- cancellation -------------------------------------------------
    def terminate(self) -> None:
        """Cancel this module: mark cancelled and kill its process group if running."""
        self._cancelled = True
        self._kill_proc()

    def _kill_proc(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass

    # ---- manifest / validation ---------------------------------------
    @classmethod
    def manifest(cls) -> dict[str, Any]:
        """Formal module descriptor used by the registry, CLI, and API."""
        return {
            "name": cls.MODULE_NAME,
            "category": cls.CATEGORY,
            "tool": cls.TOOL_BIN,
            "version": cls.VERSION,
            "description": cls.DESCRIPTION,
            "options_schema": cls.OPTIONS_SCHEMA,
            "installed": cls.is_installed(),
        }

    @classmethod
    def validate(cls) -> list[str]:
        """Return a list of interface violations ([] means the wrapper is valid)."""
        errors: list[str] = []
        if not cls.MODULE_NAME or cls.MODULE_NAME == "base":
            errors.append("MODULE_NAME must be set to a unique value")
        if cls.CATEGORY not in {"recon", "web", "auth", "misc", "exploit"}:
            errors.append(f"CATEGORY '{cls.CATEGORY}' not in recon|web|auth|misc|exploit")
        if not cls.TOOL_BIN:
            errors.append("TOOL_BIN must name the tool binary")
        if cls.build_command is BaseWrapper.build_command:
            errors.append("build_command() must be overridden")
        if cls.parse_output is BaseWrapper.parse_output:
            errors.append("parse_output() must be overridden")
        return errors

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

    def stdin_for(self, target: str) -> str | None:
        """Data to feed the tool on stdin (e.g. httpx/dnsx read targets there)."""
        return None

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

        if self._cancelled:
            result.status = ERROR
            result.error = "cancelled"
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

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
        try:
            stdin_data = self.stdin_for(target)
        except Exception:  # noqa: BLE001
            stdin_data = None
        t0 = time.monotonic()
        try:
            # Popen (not subprocess.run) so the process is killable via terminate()
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # own process group -> kill children too
            )
            self._proc = proc
            try:
                stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                self._kill_proc()
                stdout, stderr = proc.communicate()
                if self._cancelled:
                    result.status = ERROR
                    result.error = "cancelled"
                else:
                    result.status = ERROR
                    result.error = f"timed out after {timeout}s"
                result.raw_output = truncate(stdout or "")
                result.duration = round(time.monotonic() - t0, 2)
                result.finished_at = datetime.now(timezone.utc).isoformat()
                return result
            finally:
                self._proc = None
            if self._cancelled:
                result.status = ERROR
                result.error = "cancelled"
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
