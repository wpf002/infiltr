"""Quarry delegation API.

Quarry authorizes each target (human-built allowlist + valid approval) before it
calls Infiltr. Infiltr's job here is narrow: run a tiered, non-destructive scan on
exactly the one target given and return findings in Quarry's schema.

Contract (mounted under /v1/quarry so it never collides with the console's /scan):
    POST /v1/quarry/scan            -> 200 {target, assets, findings}   (synchronous)
    POST /v1/quarry/scan?wait=false -> 200 {target, job_id, status, ...} (async start)
    GET  /v1/quarry/scan/{job_id}   -> 200 {target, job_id, status, assets, findings}

Auth: Authorization: Bearer <infiltr API key or access JWT>. Always required.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .. import store
from ..engine import discover
from ..auth import service as auth_service
from ..safety import ScopeError, sanitize_target
from ..utils import base_url, hostname
from .manager import manager, ConcurrencyError
from .logging_setup import get_logger

router = APIRouter(prefix="/v1/quarry", tags=["quarry"])
log = get_logger("infiltr.quarry")

SYNC_DEADLINE = int(os.environ.get("INFILTR_QUARRY_SYNC_DEADLINE", "120"))
QUARRY_WORKERS = int(os.environ.get("INFILTR_QUARRY_WORKERS", "10"))

# Tier 1: passive/safe fingerprint + exposure + known-CVE detection (non-intrusive).
_TIER1 = ["httpx", "whatweb", "nmap", "naabu", "nuclei", "sslscan", "testssl",
          "wafw00f", "headers", "secrets", "jslibs", "katana", "gowitness", "enum4linux",
          "takeover"]
# Tier 2: + low-impact active (content discovery, XSS detection, web-server checks).
_TIER2_EXTRA = ["dalfox", "gobuster", "ffuf", "feroxbuster", "wfuzz", "nikto", "zap",
                "openredirect"]
# Never delegated: scope-expanding recon or intrusive/state-changing tools.
_NEVER = {"hydra", "metasploit", "sqlmap", "masscan", "subfinder", "theharvester", "dnsx"}


class QuarryProfile(BaseModel):
    tiers: list[int] = Field(default_factory=lambda: [1])
    tools: Optional[list[str]] = None


class QuarryScanRequest(BaseModel):
    target: str
    profile: QuarryProfile = Field(default_factory=QuarryProfile)


# ---- auth: Bearer API key or access JWT (always required) --------------
def _require_bearer(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authorization: Bearer <api-key> required")
    token = authorization.split(" ", 1)[1].strip()
    user = auth_service.resolve_api_key(token)
    if user is None:
        from ..auth import security as sec
        payload = sec.decode_token(token)
        if payload and payload.get("type") == "access":
            user = auth_service.get_user(int(payload["sub"]))
    if user is None:
        raise HTTPException(401, "invalid or expired Bearer credentials")
    return user


# ---- tier -> module resolution ----------------------------------------
def _modules_for(tiers: list[int], tools: Optional[list[str]]) -> list[str]:
    if any(t >= 3 for t in tiers):
        raise HTTPException(400, "tier 3 (high-impact) scans are never delegated; refused")
    if not any(t in (1, 2) for t in tiers):
        raise HTTPException(400, "profile.tiers must include 1 and/or 2")
    mods: set[str] = set()
    if 1 in tiers or 2 in tiers:
        mods |= set(_TIER1)
    if 2 in tiers:
        mods |= set(_TIER2_EXTRA)
    mods -= _NEVER
    if tools:
        mods &= set(tools)
    registry = discover()
    selected = sorted(m for m in mods if m in registry)
    if not selected:
        raise HTTPException(400, "no permitted, installed tools match this profile")
    return selected


def _scan_options(tiers: list[int]) -> dict[str, Any]:
    # nuclei: detection templates only — always strip intrusive/dos/fuzzing tags.
    sev = "info,low,medium,high,critical"
    return {
        # nuclei: higher throughput (rate_limit + template concurrency) so the CVE
        # sweep doesn't set the tail; still detection-only (dos/intrusive/fuzz stripped).
        "nuclei": {"severity": sev, "exclude_tags": "dos,intrusive,fuzz,fuzzing",
                   "rate_limit": 200, "concurrency": 50},
        "nmap": {"ports": "top1000"},          # service/version, no vuln NSE
        # testssl --fast: one handshake per protocol instead of per-cipher enumeration.
        "testssl": {"fast": True},
        # ZAP stays passive (spider + passive rules) for Quarry — never the active scan.
        "zap": {"mode": "baseline"},
    }


# ---- Infiltr finding -> Quarry finding --------------------------------
_SEV = {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}

_VULN_CLASS = {
    "technology": "tech-fingerprint", "title": "page-title", "http": "http-status",
    "header": "info-header", "path": "exposed-path", "finding": "web-server-issue",
    "xss": "xss", "vuln": "known-vulnerability", "tls_protocol": "weak-tls-protocol",
    "tls_cipher": "weak-tls-cipher", "tls": "tls-issue", "certificate": "tls-certificate",
    "waf": "waf-detected", "open_port": "open-port", "os": "os-fingerprint",
    "vuln_hint": "possible-vulnerability", "dbms": "dbms-detected",
    "wp_version": "wordpress-version", "wp_plugin": "wordpress-plugin", "wp_user": "wordpress-user",
    "endpoint": "discovered-endpoint", "secret": "exposed-secret", "exposure": "sensitive-file-exposure",
    "jslib": "js-library", "missing_header": "missing-security-header", "cors": "cors-misconfiguration",
    "screenshot": "screenshot-evidence", "note": "scan-note",
    "smb_share": "smb-share", "smb_user": "smb-user", "smb_group": "smb-group", "domain": "smb-domain",
    "zap_alert": "zap-alert",
    "takeover": "subdomain-takeover", "open_redirect": "open-redirect",
}


def _slug(s: str) -> str:
    import re
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return s[:48] or "finding"


def _vuln_class(f: dict) -> str:
    meta = f.get("metadata") or {}
    if f.get("type") == "vuln" and meta.get("template_id"):
        return _slug(str(meta["template_id"]))
    return _VULN_CLASS.get(f.get("type", ""), _slug(f.get("type", "finding")))


def _evidence_url(f: dict) -> str:
    meta = f.get("metadata") or {}
    return meta.get("matched_at") or meta.get("url") or (
        f.get("value") if str(f.get("value", "")).startswith("http") else "")


def _evidence(f: dict) -> dict:
    meta = f.get("metadata") or {}
    return {
        "url": _evidence_url(f),
        "detail": f.get("detail") or f.get("value") or "",
        "module": f.get("module"),
        "name": f.get("name"),
        # raw request/response when the module captured them (nuclei, zap); else empty
        "request": meta.get("request") or meta.get("curl_command") or "",
        "response": meta.get("response") or "",
        "metadata": meta,
    }


# per-finding-type confidence that the issue is real (0..1). A module may override
# with metadata.confidence (0..1). Drives Quarry's confidence>=0.8 quality gate.
_CONFIDENCE = {
    "vuln": 0.9,          # nuclei positive template match
    "exposure": 0.9,      # sensitive file returned HTTP 200 (verified fetch)
    "xss": 0.85,          # dalfox confirmed reflection/execution
    "cors": 0.85,         # ACAO reflection observed
    "takeover": 0.72,     # body signature (raised to 0.9 via metadata when CNAME confirms)
    "open_redirect": 0.8, # canary forwarded off-site
    "zap_alert": 0.7,     # active/passive alert, confidence varies (see per-risk below)
    "secret": 0.7,        # regex match in served JS — can false-positive
    "smb_share": 0.8, "smb_user": 0.8, "smb_group": 0.8,
    "wp_version": 0.6, "wp_plugin": 0.6, "wp_user": 0.6, "dbms": 0.6, "vuln_hint": 0.5,
    # informational / fingerprint types Quarry hides by default
    "technology": 0.3, "title": 0.3, "http": 0.3, "header": 0.3, "missing_header": 0.4,
    "jslib": 0.4, "open_port": 0.4, "os": 0.4, "endpoint": 0.3, "path": 0.4,
    "certificate": 0.5, "tls": 0.5, "tls_protocol": 0.6, "tls_cipher": 0.6,
    "waf": 0.5, "domain": 0.4, "note": 0.2, "screenshot": 0.3, "finding": 0.5,
}


def _confidence(f: dict) -> float:
    meta = f.get("metadata") or {}
    if isinstance(meta.get("confidence"), (int, float)):
        return max(0.0, min(1.0, float(meta["confidence"])))
    c = _CONFIDENCE.get(f.get("type", ""), 0.5)
    # a CRITICAL/HIGH finding that's only a hint shouldn't read as fully confirmed;
    # a verified finding at INFO stays low. Keep the type-based value, lightly nudged.
    if f.get("severity") in ("critical", "high") and c >= 0.7:
        c = min(1.0, c + 0.05)
    return round(c, 2)


def _location(f: dict, host: str) -> str:
    """Stable, host-independent location for the dedup key: path (+ param)."""
    meta = f.get("metadata") or {}
    url = _evidence_url(f)
    loc = ""
    if url:
        try:
            loc = urlparse(url).path or "/"
        except ValueError:
            loc = ""
    param = meta.get("param") or meta.get("parameter")
    if param:
        loc = f"{loc}?{param}"
    return loc or _slug(f.get("name") or f.get("type") or "")


def _finding_key(f: dict, vuln_class: str, host: str) -> str:
    """vulnClass:host:location — repeat scans dedup instead of piling up."""
    return f"{vuln_class}:{host.lower()}:{_location(f, host)}"


def _same_host(url: str, host: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower() == host.lower()
    except ValueError:
        return False


_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _transform(scan: dict, target: str) -> dict:
    host = hostname(target)
    assets = {base_url(target)}
    by_key: dict[str, dict] = {}
    for r in scan.get("results", []):
        for f in r.get("findings", []):
            if f.get("false_positive"):
                continue
            vuln_class = _vuln_class(f)
            severity = _SEV.get(f.get("severity", "info"), "INFO")
            key = _finding_key(f, vuln_class, host)
            item = {
                "key": key,
                "title": (f.get("name") or f.get("type") or "finding") + (f" — {f['value']}" if f.get("value") else ""),
                "vulnClass": vuln_class,
                "severity": severity,
                "confidence": _confidence(f),
                "evidence": _evidence(f),
            }
            prev = by_key.get(key)
            if prev is None:
                by_key[key] = item
            else:
                # same real issue seen again: keep the strongest, count the rest
                prev["evidence"]["occurrences"] = prev["evidence"].get("occurrences", 1) + 1
                if (_SEV_RANK[severity], item["confidence"]) > (_SEV_RANK[prev["severity"]], prev["confidence"]):
                    item["evidence"]["occurrences"] = prev["evidence"]["occurrences"]
                    by_key[key] = item
            ev_url = _evidence_url(f)
            if ev_url and _same_host(ev_url, host):
                assets.add(ev_url.rstrip("/"))
    findings = sorted(by_key.values(),
                      key=lambda x: (-_SEV_RANK[x["severity"]], -x["confidence"], x["key"]))
    return {"target": target, "assets": sorted(assets), "findings": findings}


# ---- endpoints --------------------------------------------------------
async def _launch(req: QuarryScanRequest, user: dict) -> int:
    try:
        target = sanitize_target(req.target)
    except ScopeError as exc:
        raise HTTPException(400, f"invalid target: {exc}")
    if " " in target or "," in target:
        raise HTTPException(400, "exactly one target host/URL is required")
    modules = _modules_for(req.profile.tiers, req.profile.tools)
    options = _scan_options(req.profile.tiers)
    try:
        return await manager.start_scan(
            target=target, modules=modules, options=options,
            profile=f"quarry:t{'+'.join(map(str, req.profile.tiers))}",
            user_id=user["id"], workers=QUARRY_WORKERS, skip_missing=True,
        )
    except ScopeError as exc:
        auth_service.audit("quarry.scope_rejected", actor=user["email"], user_id=user["id"],
                           detail=str(exc), target=target)
        raise HTTPException(403, f"target rejected by scope guard: {exc}")
    except ConcurrencyError as exc:
        raise HTTPException(429, str(exc))


@router.post("/scan")
async def quarry_scan(req: QuarryScanRequest, wait: bool = Query(True),
                      authorization: Optional[str] = Header(None)) -> dict:
    user = _require_bearer(authorization)
    scan_id = await _launch(req, user)
    auth_service.audit("quarry.scan", actor=user["email"], user_id=user["id"],
                       detail=f"tiers={req.profile.tiers} tools={req.profile.tools}", target=req.target)

    if not wait:
        return {"target": req.target, "job_id": scan_id, "status": "running",
                "assets": [], "findings": []}

    # synchronous: block until done, bounded by the deadline; on timeout cancel and
    # return the partial result (still 200 so Quarry's breaker doesn't trip).
    job = manager.jobs.get(scan_id)
    if job is not None:
        try:
            await asyncio.wait_for(job.done.wait(), timeout=SYNC_DEADLINE)
        except asyncio.TimeoutError:
            manager.cancel(scan_id)
            log.warning("quarry_sync_deadline", extra={"scan_id": scan_id, "target": req.target})
    scan = store.get_scan(scan_id, user_id=user["id"])
    if scan is None:
        raise HTTPException(500, "scan record missing after run")
    return _transform(scan, req.target)


@router.get("/scan/{job_id}")
async def quarry_scan_status(job_id: int, authorization: Optional[str] = Header(None)) -> dict:
    user = _require_bearer(authorization)
    scan = store.get_scan(job_id, user_id=user["id"])
    if scan is None:
        raise HTTPException(404, "job not found")
    result = _transform(scan, scan["target"])
    result["job_id"] = job_id
    result["status"] = scan["status"]
    return result
