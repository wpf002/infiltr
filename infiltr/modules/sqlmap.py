"""sqlmap wrapper — SQL injection detection/exploitation."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_HIGH, SEV_CRITICAL
from ..utils import normalize_url, strip_ansi

_PARAM_RE = re.compile(r"Parameter:\s*(.+?)\s*\(", re.I)
_TYPE_RE = re.compile(r"Type:\s*(.+)", re.I)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_DB_RE = re.compile(r"available databases \[\d+\]:", re.I)


class SqlmapWrapper(BaseWrapper):
    MODULE_NAME = "sqlmap"
    CATEGORY = "web"
    TOOL_BIN = "sqlmap"
    DESCRIPTION = "Automated SQL injection detection and exploitation"
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        url = normalize_url(target)
        cmd = [
            self.TOOL_BIN,
            "-u", url,
            "--level", str(self.options.get("level", 1)),
            "--risk", str(self.options.get("risk", 1)),
            "--flush-session",
        ]
        if self.options.get("batch", True):
            cmd.append("--batch")
        crawl = int(self.options.get("crawl", 0))
        if crawl:
            cmd += ["--crawl", str(crawl)]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []

        dbms = _DBMS_RE.search(text)
        if dbms:
            findings.append(
                Finding(type="dbms", name="back-end DBMS", value=dbms.group(1).strip(), severity=SEV_INFO)
            )

        params = _PARAM_RE.findall(text)
        types = _TYPE_RE.findall(text)
        for p in params:
            findings.append(
                Finding(
                    type="sqli",
                    name="injectable parameter",
                    value=p.strip(),
                    detail="; ".join(t.strip() for t in types[:4]),
                    severity=SEV_CRITICAL,
                )
            )

        if not params and re.search(r"is vulnerable|might be injectable|appears to be", text, re.I):
            findings.append(
                Finding(
                    type="sqli",
                    name="possible injection",
                    value="parameter flagged",
                    detail="sqlmap flagged a parameter as potentially injectable",
                    severity=SEV_HIGH,
                )
            )

        if _DB_RE.search(text):
            block = text[_DB_RE.search(text).end():]
            for line in block.splitlines():
                s = line.strip().lstrip("[*] ").strip()
                if s and not s.startswith("[") and len(s) < 64 and re.match(r"^[\w$-]+$", s):
                    findings.append(Finding(type="database", name="database", value=s, severity=SEV_INFO))
                elif s.startswith("["):
                    break

        # Table listings: "Database: dvwa\n[2 tables]\n+---+\n| users |\n..."
        for m in re.finditer(r"Database:\s*(\S+)\s*\n\s*\[\d+ tables?\](.*?)(?:\n\n|\Z)", text, re.S | re.I):
            db = m.group(1)
            for row in re.findall(r"\|\s*([\w$-]+)\s*\|", m.group(2)):
                findings.append(
                    Finding(
                        type="table",
                        name="table",
                        value=row,
                        detail=f"database {db}",
                        severity=SEV_INFO,
                        metadata={"database": db},
                    )
                )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        inj = [f for f in findings if f.type == "sqli"]
        return f"{len(inj)} injectable point(s)." if inj else "No injection found."
