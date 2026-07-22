"""FastAPI application exposing scans, modules, history, and live progress."""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import store
from ..engine import module_status, discover
from .manager import manager

app = FastAPI(title="Infiltr API", version="0.12.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("INFILTR_CORS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- schemas ----------------------------------------------------------
class ScanRequest(BaseModel):
    target: str = Field(..., examples=["http://localhost:8080"])
    modules: Optional[list[str]] = None
    profile: Optional[str] = None
    options: Optional[dict[str, Any]] = None
    skip_missing: bool = False
    workers: int = 4


class ScanStarted(BaseModel):
    scan_id: int
    target: str
    modules: list[str]


# ---- routes -----------------------------------------------------------
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "infiltr"}


@app.get("/modules")
def modules() -> list[dict[str, Any]]:
    return module_status()


@app.post("/scan", response_model=ScanStarted)
async def start_scan(req: ScanRequest) -> ScanStarted:
    from ..profiles import resolve_modules, resolve_options
    modules = resolve_modules(req.profile, req.modules)
    registry = discover()
    selected = [m for m in modules if m in registry] if modules else list(registry)
    if not selected:
        raise HTTPException(400, "no valid modules selected")
    # merge profile options under any explicit request options
    options = {**resolve_options(req.profile), **(req.options or {})}
    scan_id = await manager.start_scan(
        target=req.target,
        modules=selected,
        options=options,
        profile=req.profile,
        workers=req.workers,
        skip_missing=req.skip_missing,
    )
    return ScanStarted(scan_id=scan_id, target=req.target, modules=selected)


# ---- profiles ---------------------------------------------------------
class ProfileBody(BaseModel):
    name: str
    modules: list[str] = []
    description: str = ""
    target: Optional[str] = None
    options: Optional[dict[str, Any]] = None


@app.get("/profiles")
def list_profiles() -> list[dict[str, Any]]:
    from ..profiles import all_profiles
    return all_profiles()


@app.post("/profiles")
def create_profile(body: ProfileBody) -> dict[str, Any]:
    return store.create_profile(
        name=body.name, modules=body.modules, description=body.description,
        target=body.target, options=body.options,
    )


@app.put("/profiles/{profile_id}")
def update_profile(profile_id: int, body: ProfileBody) -> dict[str, Any]:
    prof = store.update_profile(
        profile_id, name=body.name, modules=body.modules,
        description=body.description, target=body.target, options=body.options,
    )
    if prof is None:
        raise HTTPException(404, "profile not found")
    return prof


@app.delete("/profiles/{profile_id}")
def delete_profile(profile_id: int) -> dict[str, Any]:
    if not store.delete_profile(profile_id):
        raise HTTPException(404, "profile not found")
    return {"deleted": profile_id}


@app.get("/scans")
def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    return store.list_scans(limit=limit)


@app.get("/scan/{scan_id}")
def get_scan(scan_id: int) -> dict[str, Any]:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: int) -> dict[str, Any]:
    if not store.delete_scan(scan_id):
        raise HTTPException(404, "scan not found")
    return {"deleted": scan_id}


class AskBody(BaseModel):
    question: str


@app.post("/scan/{scan_id}/analyze")
def analyze_scan(scan_id: int) -> dict[str, Any]:
    from ..ai import flint
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return {
        "scan_id": scan_id,
        "mode": "online" if flint.online else "offline",
        "summary": flint.summarize(scan),
        "most_critical": flint.most_critical(scan),
        "attack_paths": flint.attack_paths(scan),
    }


@app.post("/scan/{scan_id}/ask")
def ask_scan(scan_id: int, body: AskBody) -> dict[str, Any]:
    from ..ai import flint
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return {"scan_id": scan_id, "question": body.question, "answer": flint.ask(scan, body.question)}


@app.post("/scan/{scan_id}/flag-fp")
def flag_false_positives(scan_id: int, apply: bool = False) -> dict[str, Any]:
    from ..ai import flint
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    flagged = flint.flag_false_positives(scan)
    applied = store.mark_false_positives(scan_id, flagged) if apply else 0
    return {"scan_id": scan_id, "flagged": flagged, "applied": applied}


@app.get("/scan/{scan_id}/report")
def scan_report(scan_id: int, format: str = "html", client: str = "") -> Response:
    from ..reporting import render_html, render_markdown, render_pdf, ReportTheme, PDF_AVAILABLE
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    theme = ReportTheme(client=client)
    fmt = format.lower()
    if fmt in ("md", "markdown"):
        return Response(render_markdown(scan, theme), media_type="text/markdown",
                        headers={"Content-Disposition": f'inline; filename="infiltr-scan-{scan_id}.md"'})
    if fmt == "pdf":
        if not PDF_AVAILABLE:
            raise HTTPException(501, "PDF generation unavailable (WeasyPrint not installed); use format=html or md")
        return Response(render_pdf(scan, theme), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="infiltr-scan-{scan_id}.pdf"'})
    return Response(render_html(scan, theme), media_type="text/html")


@app.get("/scan/{scan_id}/events")
async def scan_events(scan_id: int, request: Request) -> StreamingResponse:
    """Server-Sent Events stream of live scan progress."""
    async def event_gen():
        async for evt in manager.subscribe(scan_id):
            if await request.is_disconnected():
                break
            yield f"event: {evt.get('type', 'message')}\ndata: {json.dumps(evt)}\n\n"
        yield "event: close\ndata: {}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ---- static frontend (single-origin dev) -----------------------------
# Mounted LAST at "/" so API routes above win; unmatched paths (index.html,
# styles.css, app.js, …) are served from the frontend directory.
_FRONTEND = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")
if os.path.isdir(_FRONTEND):
    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="frontend")
