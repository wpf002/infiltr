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
          "wafw00f", "headers", "secrets", "jslibs", "katana", "gowitness", "enum4linux"]
# Tier 2: + low-impact active (content discovery, XSS detection, web-server checks).
_TIER2_EXTRA = ["dalfox", "gobuster", "ffuf", "feroxbuster", "wfuzz", "nikto", "zap"]
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


def _evidence(f: dict) -> dict:
    meta = f.get("metadata") or {}
    url = meta.get("matched_at") or meta.get("url") or (f.get("value") if str(f.get("value", "")).startswith("http") else "")
    return {
        "url": url,
        "detail": f.get("detail") or f.get("value") or "",
        "module": f.get("module"),
        "name": f.get("name"),
        "metadata": meta,
    }


def _same_host(url: str, host: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower() == host.lower()
    except ValueError:
        return False


def _transform(scan: dict, target: str) -> dict:
    host = hostname(target)
    assets = {base_url(target)}
    findings = []
    for r in scan.get("results", []):
        for f in r.get("findings", []):
            if f.get("false_positive"):
                continue
            findings.append({
                "title": (f.get("name") or f.get("type") or "finding") + (f" — {f['value']}" if f.get("value") else ""),
                "vulnClass": _vuln_class(f),
                "severity": _SEV.get(f.get("severity", "info"), "INFO"),
                "evidence": _evidence(f),
            })
            ev_url = (f.get("metadata") or {}).get("matched_at") or (f.get("value") if str(f.get("value", "")).startswith("http") else "")
            if ev_url and _same_host(ev_url, host):
                assets.add(ev_url.rstrip("/"))
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
