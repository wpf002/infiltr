"""Native error-based SQL-injection detection (low-impact active, single target).

Non-destructive: injects a single quote / broken-syntax marker into query
parameters and looks for database error signatures in the response, compared
against a clean baseline. GET only, no data modification, bounded probe count,
no crawling. This is DETECTION, not exploitation (sqlmap is never delegated)."""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..webutil import fetch

# Common DB error signatures across engines. A match that appears with the
# payload but NOT in the clean baseline is a strong error-based SQLi signal.
_SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning:\s*mysqli?|mysql_fetch|"
    r"mysqlsyntaxerror|valid mysql result|com\.mysql\.jdbc|"
    r"pg_query|postgresql.*error|syntax error at or near|pdoexception|"
    r"unclosed quotation mark after the character string|microsoft sql server|"
    r"odbc sql server driver|sqlserver jdbc|system\.data\.sqlclient|"
    r"ora-0\d{4}|oracle error|quoted string not properly terminated|"
    r"sqlite3?\.(operational|programming)error|sqlite_error|unrecognized token|"
    r"sql syntax.*error|unterminated quoted string)",
    re.I)

# common injectable param names to try when the URL has none of its own
_PARAMS = ["id", "user", "userid", "user_id", "page", "search", "q", "query",
           "cat", "category", "item", "product", "pid", "order", "sort", "name"]
_MARKERS = ["'", "')", "\"", "1'\"", "' OR '1'='1"]


class SqliDetectWrapper(NativeWrapper):
    MODULE_NAME = "sqli_detect"
    CATEGORY = "web"
    DESCRIPTION = "Error-based SQL-injection detection on the target URL's query params (safe, no exploitation)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 90

    def collect(self, target: str) -> list[Finding]:
        timeout = int(self.options.get("timeout", 12))
        parsed = urlparse(target)
        existing = dict(parse_qsl(parsed.query))
        names = list(dict.fromkeys(list(existing.keys()) + _PARAMS))[:12]

        findings: list[Finding] = []
        for name in names:
            # baseline with a benign value; if it already errors, skip (not our signal)
            base_val = existing.get(name, "1")
            baseline = fetch(self._with_param(parsed, existing, name, base_val),
                             timeout=timeout, headers=self.auth_headers())
            if _SQL_ERRORS.search(baseline.get("body", "") or ""):
                continue
            for marker in _MARKERS:
                probe_url = self._with_param(parsed, existing, name, base_val + marker)
                r = fetch(probe_url, timeout=timeout, headers=self.auth_headers())
                m = _SQL_ERRORS.search(r.get("body", "") or "")
                if m:
                    findings.append(Finding(
                        type="sqli", name=f"error-based SQL injection via '{name}'", value=probe_url,
                        detail=f"parameter '{name}' surfaced a database error with payload {marker!r}: {m.group(0)[:80]}",
                        severity=SEV_HIGH,
                        metadata={"param": name, "url": probe_url, "matched_at": probe_url,
                                  "payload": marker, "error": m.group(0)[:120], "confidence": 0.85}))
                    break  # one confirmation per param is enough
        if not findings:
            findings.append(Finding(type="note", name="sqli", value="none",
                                    detail="no database error surfaced by injection markers",
                                    severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "sqli")
        return f"{n} SQL-injection point(s)." if n else "No SQL injection detected."

    @staticmethod
    def _with_param(parsed, existing: dict, name: str, value: str) -> str:
        q = dict(existing)
        q[name] = value
        return urlunparse(parsed._replace(query=urlencode(q)))
