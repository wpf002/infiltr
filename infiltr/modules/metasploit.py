"""Metasploit wrapper — run an MSF module (auxiliary scanner by default).

Drives the framework non-interactively via ``msfconsole -q -x``. Defaults to a
safe auxiliary HTTP scanner; point it at any module (including exploits) via
options for authorized testing — the engine's target allow/block scope guard
still applies to RHOSTS.

    options.metasploit = {
      "module": "auxiliary/scanner/http/http_login",
      "opts": {"USERPASS_FILE": "/app/lab/wordlists/...", "AUTH_URI": "/"},
      "payload": "cmd/unix/reverse",     # exploit modules only
    }
"""
from __future__ import annotations

import re

from ..base import (
    BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
)
from ..utils import host_port, base_url, strip_ansi
from urllib.parse import urlparse

_PLUS_RE = re.compile(r"^\[\+\]\s*(.+)$", re.M)
_SESSION_RE = re.compile(r"(meterpreter session \d+ opened|command shell session \d+ opened)", re.I)
_LOGIN_RE = re.compile(r"(?:Success(?:ful)?:?|LOGIN SUCCESSFUL:?)\s*'?([^\s']+):([^\s'(]+)", re.I)


class MetasploitWrapper(BaseWrapper):
    MODULE_NAME = "metasploit"
    CATEGORY = "exploit"
    TOOL_BIN = "msfconsole"
    DESCRIPTION = "Run a Metasploit module (auxiliary scanner by default)"
    VERSION = "1.0"
    OPTIONS_SCHEMA = {
        "module": {"type": "string", "default": "auxiliary/scanner/http/http_version",
                   "help": "MSF module path"},
        "opts": {"type": "dict", "default": {}, "help": "extra 'set KEY VALUE' datastore options"},
        "payload": {"type": "string", "default": "", "help": "payload for exploit modules"},
    }
    DEFAULT_TIMEOUT = 600

    # datastore keys a user must never set (would bypass the scoped target or
    # turn a scanner into a reverse shell); RHOSTS/RPORT are set by the wrapper.
    _FORBIDDEN_OPTS = {"RHOSTS", "RPORT", "LHOST", "LPORT", "SRVHOST", "SRVPORT",
                       "PAYLOAD", "SESSION", "CMD"}
    _SET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def build_command(self, target: str) -> list[str]:
        import os
        host, port = host_port(target)
        scheme = urlparse(base_url(target)).scheme
        rport = port or (443 if scheme == "https" else 80)
        module = str(self.options.get("module", "auxiliary/scanner/http/http_version")).strip()

        # only auxiliary modules by default — exploit/payload use needs an explicit
        # operator opt-in (INFILTR_MSF_ALLOW_EXPLOIT) and is never user-reachable in SaaS.
        allow_exploit = os.environ.get("INFILTR_MSF_ALLOW_EXPLOIT", "0") in ("1", "true", "True")
        if not module.startswith("auxiliary/") and not allow_exploit:
            raise ValueError("only auxiliary/ modules are permitted (set INFILTR_MSF_ALLOW_EXPLOIT to allow others)")
        if not re.match(r"^[A-Za-z0-9_/]+$", module):
            raise ValueError("invalid module path")

        cmds = [f"use {module}", f"set RHOSTS {host}", f"set RPORT {rport}"]
        if scheme == "https":
            cmds.append("set SSL true")
        if allow_exploit:
            payload = self.options.get("payload")
            if payload and re.match(r"^[A-Za-z0-9_/]+$", str(payload)):
                cmds.append(f"set PAYLOAD {payload}")
        for key, val in (self.options.get("opts") or {}).items():
            k = str(key)
            if k.upper() in self._FORBIDDEN_OPTS or not self._SET_RE.match(k):
                continue  # drop scope-bypass / shell keys
            sval = str(val)
            if any(c in sval for c in ";\n\r`|&$"):
                continue  # drop injected metachars
            cmds.append(f"set {k} {sval}")
        cmds += ["run", "exit -y"]

        resource = "; ".join(cmds)
        return [self.TOOL_BIN, "-q", "-n", "-x", resource]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []

        if _SESSION_RE.search(text):
            m = _SESSION_RE.search(text)
            findings.append(Finding(type="session", name="session opened", value=m.group(1),
                                    detail="Metasploit opened a session on the target",
                                    severity=SEV_CRITICAL))

        for login, pw in _LOGIN_RE.findall(text):
            findings.append(Finding(type="credential", name=f"{login}:{pw}", value="via msf",
                                    detail="valid login found by Metasploit module",
                                    severity=SEV_CRITICAL,
                                    metadata={"login": login, "password": pw}))

        for line in _PLUS_RE.findall(text):
            low = line.lower()
            if any(k in low for k in ("session", "successful", "success:")):
                continue  # already captured above
            sev = SEV_MEDIUM if any(k in low for k in ("vulnerable", "exploit", "found")) else SEV_LOW
            findings.append(Finding(type="msf", name="result", value=line.strip()[:200], severity=sev))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        crit = sum(1 for f in findings if f.severity == SEV_CRITICAL)
        if crit:
            return f"{crit} critical result(s) (session/credential)."
        return f"{len(findings)} result(s)." if findings else "No results."
