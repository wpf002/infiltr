"""Flint — the LLM abstraction layer.

Hard invariant: Flint *annotates and explains*. It never assigns or overrides
severity (the deterministic engine owns that) and never fabricates findings —
every answer is grounded in the structured scan data passed to it.

Runs against the Anthropic API when a key is present; otherwise falls back to
deterministic heuristics so the feature is always usable and testable offline.
"""
from __future__ import annotations

import json
import os
from typing import Any

from ..base import severity_rank, SEVERITY_ORDER

DEFAULT_MODEL = os.environ.get("INFILTR_AI_MODEL", "claude-sonnet-4-6")
MAX_TOKENS = int(os.environ.get("INFILTR_AI_MAX_TOKENS", "1024"))

SYSTEM_PROMPT = (
    "You are Flint, the analysis layer of the Infiltr security scanner. "
    "You ONLY explain and prioritize findings that are given to you as structured JSON. "
    "Strict rules:\n"
    "1. NEVER invent findings, hosts, ports, or vulnerabilities not present in the data.\n"
    "2. NEVER assign or change a severity — the deterministic engine already scored every "
    "finding; treat the given severity as authoritative.\n"
    "3. Be concise, technical, and actionable. Reference findings by module + name.\n"
    "4. This is authorized security testing; suggest next investigative steps, not real-world attacks "
    "against third parties.\n"
    "If the data is empty, say so plainly."
)


def _compact_context(scan: dict[str, Any]) -> dict[str, Any]:
    """Structured, token-lean view of a scan for the model — no raw tool dumps."""
    return {
        "target": scan.get("target"),
        "top_severity": scan.get("top_severity"),
        "finding_count": scan.get("finding_count"),
        "modules": [
            {
                "module": r.get("module"),
                "category": r.get("category"),
                "status": r.get("status"),
                "severity": r.get("severity"),
                "summary": r.get("summary"),
                "findings": [
                    {
                        "type": f.get("type"),
                        "name": f.get("name"),
                        "value": f.get("value"),
                        "detail": f.get("detail"),
                        "severity": f.get("severity"),
                    }
                    for f in r.get("findings", [])
                ],
            }
            for r in scan.get("results", [])
        ],
    }


def _all_findings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for r in scan.get("results", []):
        for f in r.get("findings", []):
            out.append({**f, "module": r.get("module")})
    return out


class Flint:
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("INFILTR_ANTHROPIC_API_KEY")
        self._client = None
        if self.api_key:
            try:
                import anthropic  # noqa: F401
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except Exception:  # noqa: BLE001
                self._client = None

    @property
    def online(self) -> bool:
        return self._client is not None

    # ---- low level ----------------------------------------------------
    def _complete(self, user_prompt: str, context: dict[str, Any]) -> str:
        payload = f"{user_prompt}\n\nSCAN DATA (JSON):\n{json.dumps(context, indent=2)}"
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": payload}],
        )
        return "".join(getattr(block, "text", "") for block in resp.content).strip()

    # ---- public API ---------------------------------------------------
    def summarize(self, scan: dict[str, Any]) -> str:
        if self.online:
            return self._complete(
                "Write a 3-5 sentence executive summary of this scan: what was found, "
                "the most important risks, and the overall posture.",
                _compact_context(scan),
            )
        return self._offline_summary(scan)

    def most_critical(self, scan: dict[str, Any]) -> str:
        if self.online:
            return self._complete(
                "What is the single most critical finding and why? Name the module and finding, "
                "explain the impact in 2-3 sentences. Do not restate its severity as your own judgment.",
                _compact_context(scan),
            )
        return self._offline_most_critical(scan)

    def attack_paths(self, scan: dict[str, Any]) -> list[str]:
        if self.online:
            text = self._complete(
                "Given these findings, list up to 5 concrete next investigative steps a tester "
                "should take, as a plain numbered list. Chain related findings (e.g. an open DB port "
                "plus a SQLi). One line each.",
                _compact_context(scan),
            )
            steps = [ln.strip(" -*0123456789.").strip() for ln in text.splitlines() if ln.strip()]
            return [s for s in steps if s][:5]
        return self._offline_attack_paths(scan)

    def ask(self, scan: dict[str, Any], question: str) -> str:
        if self.online:
            return self._complete(
                f"Answer this question using ONLY the scan data: {question}",
                _compact_context(scan),
            )
        return self._offline_answer(scan, question)

    def flag_false_positives(self, scan: dict[str, Any]) -> list[dict[str, Any]]:
        """Return findings that look like noise, with a reason. Never deletes; suggests."""
        if self.online:
            text = self._complete(
                "Identify findings that are likely false positives or low-signal noise "
                "(e.g. generic nikto/wfuzz info entries). Reply as a JSON array of objects "
                '{"module","name","reason"}. Only include genuine likely-noise items.',
                _compact_context(scan),
            )
            try:
                data = json.loads(text[text.find("["): text.rfind("]") + 1])
                if isinstance(data, list):
                    return data
            except Exception:  # noqa: BLE001
                pass
            return []
        return self._offline_false_positives(scan)

    # ---- offline heuristics ------------------------------------------
    def _offline_summary(self, scan: dict[str, Any]) -> str:
        findings = _all_findings(scan)
        if not findings:
            return (f"Scan of {scan.get('target')} completed with no findings across "
                    f"{scan.get('module_count', 0)} module(s).")
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
        highlights = ", ".join(
            f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts[s]
        )
        top = self._offline_most_critical(scan)
        return (
            f"Scan of {scan.get('target')} surfaced {len(findings)} finding(s) ({highlights}). "
            f"Highest severity: {scan.get('top_severity', 'info').upper()}. {top} "
            "[offline heuristic — set ANTHROPIC_API_KEY for LLM analysis]"
        )

    def _offline_most_critical(self, scan: dict[str, Any]) -> str:
        findings = _all_findings(scan)
        if not findings:
            return "No findings to prioritize."
        worst = max(findings, key=lambda f: severity_rank(f.get("severity")))
        return (
            f"Most critical: {worst['module']} — {worst.get('name')} "
            f"{worst.get('value', '')} ({worst.get('severity', 'info')})."
        ).strip()

    def _offline_attack_paths(self, scan: dict[str, Any]) -> list[str]:
        findings = _all_findings(scan)
        types = {f.get("type") for f in findings}
        paths: list[str] = []
        if "sqli" in types:
            paths.append("Confirm the SQL injection and enumerate databases/tables (sqlmap --dbs --tables).")
        if "credential" in types:
            paths.append("Reuse the discovered credentials to authenticate and probe post-auth surface.")
        if any(f.get("type") == "open_port" and f.get("value") in {"mysql", "postgresql", "mongodb", "redis"} for f in findings):
            paths.append("Attempt direct access to the exposed database service from an allowed host.")
        if "xss" in types:
            paths.append("Weaponize the reflected XSS context to test session/cookie exposure.")
        if "path" in types:
            paths.append("Review discovered paths (admin/config/backup) for unauthenticated access.")
        if "subdomain" in types:
            paths.append("Expand scope to discovered subdomains and re-run recon.")
        return paths[:5] or ["No obvious chains; broaden recon or increase scan depth."]

    def _offline_answer(self, scan: dict[str, Any], question: str) -> str:
        q = question.lower()
        if "critical" in q or "worst" in q or "most" in q:
            return self._offline_most_critical(scan)
        if "how many" in q or "count" in q:
            return f"{scan.get('finding_count', 0)} finding(s) across {scan.get('module_count', 0)} module(s)."
        if "summary" in q or "overview" in q:
            return self._offline_summary(scan)
        return (
            "Offline mode can answer about the most critical finding, counts, or a summary. "
            "Set ANTHROPIC_API_KEY for full natural-language Q&A."
        )

    def _offline_false_positives(self, scan: dict[str, Any]) -> list[dict[str, Any]]:
        noise = []
        for r in scan.get("results", []):
            if r.get("module") not in {"nikto", "wfuzz"}:
                continue
            for f in r.get("findings", []):
                detail = (f.get("detail", "") + f.get("name", "")).lower()
                if f.get("severity") in ("info", "low") and any(
                    k in detail for k in ("etag", "inode", "x-content", "banner", "allowed http")
                ):
                    noise.append({
                        "module": r.get("module"),
                        "name": f.get("name"),
                        "reason": "Generic informational entry — commonly low-signal / noise.",
                    })
        return noise


flint = Flint()
