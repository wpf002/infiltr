"""FastAPI application exposing scans, modules, history, and live progress."""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import store
from ..engine import module_status, discover
from ..auth import service as auth_service
from ..auth.deps import current_user, require_user, require_role, rate_limit, user_id_of, AUTH_ENABLED
from .manager import manager
from ..scheduler.service import Scheduler

app = FastAPI(title="Infiltr API", version="0.12.0")

_scheduler = Scheduler(manager)
SCHEDULER_ENABLED = os.environ.get("INFILTR_SCHEDULER", "0") in ("1", "true", "True")


@app.on_event("startup")
async def _start_scheduler() -> None:
    if SCHEDULER_ENABLED:
        _scheduler.start()


@app.on_event("shutdown")
async def _stop_scheduler() -> None:
    await _scheduler.stop()

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("INFILTR_CORS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def no_cache_frontend(request, call_next):
    """Revalidate the console assets so UI changes always take (no stale JS/CSS)."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


# ---- schemas ----------------------------------------------------------
class ScanRequest(BaseModel):
    target: str = Field(..., examples=["http://localhost:8080"])
    modules: Optional[list[str]] = None
    profile: Optional[str] = None
    options: Optional[dict[str, Any]] = None
    skip_missing: bool = False
    workers: int = 6


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


@app.get("/explanations")
def explanations() -> dict[str, Any]:
    """Plain-English descriptions for every module and finding type."""
    from ..explain import all_explanations
    return all_explanations()


@app.get("/modules/invalid")
def modules_invalid() -> dict[str, Any]:
    from ..engine import invalid_modules
    return invalid_modules()


@app.post("/modules/reload")
def modules_reload(user=Depends(require_role("admin") if AUTH_ENABLED else current_user)) -> dict[str, Any]:
    """Hot-reload the wrapper registry without restarting the server."""
    from ..engine import reload as reload_modules, invalid_modules
    reg = reload_modules()
    return {"reloaded": sorted(reg.keys()), "invalid": invalid_modules()}


@app.post("/scan", response_model=ScanStarted)
async def start_scan(req: ScanRequest, user=Depends(current_user), _rl=Depends(rate_limit)) -> ScanStarted:
    from ..profiles import resolve_modules, resolve_options
    uid = user_id_of(user)
    modules = resolve_modules(req.profile, req.modules, user_id=uid)
    registry = discover()
    selected = [m for m in modules if m in registry] if modules else list(registry)
    if not selected:
        raise HTTPException(400, "no valid modules selected")
    # merge profile options under any explicit request options
    options = {**resolve_options(req.profile, user_id=uid), **(req.options or {})}
    from ..safety import ScopeError
    from .manager import ConcurrencyError
    try:
        scan_id = await manager.start_scan(
            target=req.target,
            modules=selected,
            options=options,
            profile=req.profile,
            user_id=uid,
            workers=req.workers,
            skip_missing=req.skip_missing,
        )
    except ScopeError as exc:
        raise HTTPException(403, f"target rejected: {exc}")
    except ConcurrencyError as exc:
        raise HTTPException(429, str(exc))
    auth_service.audit("scan.start", actor=(user or {}).get("email", "anon"),
                       user_id=uid, detail=",".join(selected), target=req.target)
    return ScanStarted(scan_id=scan_id, target=req.target, modules=selected)


# ---- profiles ---------------------------------------------------------
class ProfileBody(BaseModel):
    name: str
    modules: list[str] = []
    description: str = ""
    target: Optional[str] = None
    options: Optional[dict[str, Any]] = None


@app.get("/profiles")
def list_profiles(user=Depends(current_user)) -> list[dict[str, Any]]:
    from ..profiles import all_profiles
    return all_profiles(user_id=user_id_of(user))


@app.post("/profiles")
def create_profile(body: ProfileBody, user=Depends(current_user)) -> dict[str, Any]:
    return store.create_profile(
        name=body.name, modules=body.modules, description=body.description,
        target=body.target, options=body.options, user_id=user_id_of(user),
    )


@app.put("/profiles/{profile_id}")
def update_profile(profile_id: int, body: ProfileBody, user=Depends(current_user)) -> dict[str, Any]:
    prof = store.update_profile(
        profile_id, user_id=user_id_of(user), name=body.name, modules=body.modules,
        description=body.description, target=body.target, options=body.options,
    )
    if prof is None:
        raise HTTPException(404, "profile not found")
    return prof


@app.delete("/profiles/{profile_id}")
def delete_profile(profile_id: int, user=Depends(current_user)) -> dict[str, Any]:
    if not store.delete_profile(profile_id, user_id=user_id_of(user)):
        raise HTTPException(404, "profile not found")
    return {"deleted": profile_id}


# ---- auth -------------------------------------------------------------
class RegisterBody(BaseModel):
    email: str
    password: str = Field(..., min_length=6)


class LoginBody(BaseModel):
    email: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class ApiKeyBody(BaseModel):
    name: str = ""


class UserUpdateBody(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None


@app.get("/auth/config")
def auth_config() -> dict[str, Any]:
    return {"auth_enabled": AUTH_ENABLED, "user_count": auth_service.user_count()}


@app.post("/auth/register")
def register(body: RegisterBody) -> dict[str, Any]:
    try:
        user = auth_service.create_user(body.email, body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    auth_service.audit("user.register", actor=user["email"], user_id=user["id"], detail=user["role"])
    return {"user": user, **auth_service.issue_tokens(user)}


@app.post("/auth/login")
def login(body: LoginBody) -> dict[str, Any]:
    user = auth_service.authenticate(body.email, body.password)
    if user is None:
        raise HTTPException(401, "invalid credentials")
    auth_service.audit("user.login", actor=user["email"], user_id=user["id"])
    return {"user": user, **auth_service.issue_tokens(user)}


@app.post("/auth/refresh")
def refresh(body: RefreshBody) -> dict[str, Any]:
    from ..auth import security as sec
    payload = sec.decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(401, "invalid refresh token")
    user = auth_service.get_user(int(payload["sub"]))
    if user is None:
        raise HTTPException(401, "user not found")
    return auth_service.issue_tokens(user)


@app.get("/auth/me")
def me(user=Depends(require_user)) -> dict[str, Any]:
    return user


@app.post("/auth/api-keys")
def create_api_key(body: ApiKeyBody, user=Depends(require_user)) -> dict[str, Any]:
    return auth_service.create_api_key(user["id"], body.name)


@app.get("/auth/api-keys")
def list_api_keys(user=Depends(require_user)) -> list[dict[str, Any]]:
    return auth_service.list_api_keys(user["id"])


@app.delete("/auth/api-keys/{key_id}")
def revoke_api_key(key_id: int, user=Depends(require_user)) -> dict[str, Any]:
    if not auth_service.revoke_api_key(user["id"], key_id):
        raise HTTPException(404, "key not found")
    return {"revoked": key_id}


# ---- admin ------------------------------------------------------------
@app.get("/admin/users")
def admin_users(user=Depends(require_role("admin"))) -> list[dict[str, Any]]:
    return auth_service.list_users()


@app.put("/admin/users/{user_id}")
def admin_update_user(user_id: int, body: UserUpdateBody, user=Depends(require_role("admin"))) -> dict[str, Any]:
    try:
        updated = auth_service.update_user(user_id, role=body.role, is_active=body.is_active)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if updated is None:
        raise HTTPException(404, "user not found")
    auth_service.audit("user.update", actor=user["email"], user_id=user["id"], detail=str(user_id))
    return updated


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int, user=Depends(require_role("admin"))) -> dict[str, Any]:
    if not auth_service.delete_user(user_id):
        raise HTTPException(404, "user not found")
    auth_service.audit("user.delete", actor=user["email"], user_id=user["id"], detail=str(user_id))
    return {"deleted": user_id}


@app.get("/admin/audit")
def admin_audit(limit: int = 100, user=Depends(require_role("admin"))) -> list[dict[str, Any]]:
    return auth_service.list_audit(limit=limit)


@app.get("/scans")
def list_scans(limit: int = 50, user=Depends(current_user)) -> list[dict[str, Any]]:
    return store.list_scans(limit=limit, user_id=user_id_of(user))


@app.get("/scan/{scan_id}")
def get_scan(scan_id: int, user=Depends(current_user)) -> dict[str, Any]:
    scan = store.get_scan(scan_id, user_id=user_id_of(user))
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


@app.post("/scan/{scan_id}/cancel")
def cancel_scan(scan_id: int, user=Depends(current_user)) -> dict[str, Any]:
    scan = store.get_scan(scan_id, user_id=user_id_of(user))
    if scan is None:
        raise HTTPException(404, "scan not found")
    stopped = manager.cancel(scan_id)
    auth_service.audit("scan.cancel", actor=(user or {}).get("email", "anon"),
                       user_id=user_id_of(user), detail=str(scan_id))
    return {"scan_id": scan_id, "cancelled": stopped}


@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: int, user=Depends(current_user)) -> dict[str, Any]:
    if not store.delete_scan(scan_id, user_id=user_id_of(user)):
        raise HTTPException(404, "scan not found")
    auth_service.audit("scan.delete", actor=(user or {}).get("email", "anon"),
                       user_id=user_id_of(user), detail=str(scan_id))
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


@app.get("/scan/{scan_id}/delta")
def scan_delta(scan_id: int, user=Depends(current_user)) -> dict[str, Any]:
    scan = store.get_scan(scan_id, user_id=user_id_of(user))
    if scan is None:
        raise HTTPException(404, "scan not found")
    return store.scan_delta(scan_id)


@app.get("/targets/trend")
def target_trend(target: str, user=Depends(current_user)) -> list[dict[str, Any]]:
    return store.target_trend(target, user_id=user_id_of(user))


# ---- schedules --------------------------------------------------------
class ScheduleBody(BaseModel):
    target: str
    cron: str = "0 * * * *"
    name: str = ""
    profile: Optional[str] = None
    alerts: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None


@app.get("/schedules")
def list_schedules(user=Depends(current_user)) -> list[dict[str, Any]]:
    return store.list_schedules(user_id=user_id_of(user))


@app.post("/schedules")
def create_schedule(body: ScheduleBody, user=Depends(current_user)) -> dict[str, Any]:
    from ..scheduler import validate_cron
    if not validate_cron(body.cron):
        raise HTTPException(400, "invalid cron expression (expected: min hr dom mon dow)")
    return store.create_schedule(
        target=body.target, cron=body.cron, name=body.name, profile=body.profile,
        alerts=body.alerts, user_id=user_id_of(user),
    )


@app.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: int, user=Depends(current_user)) -> dict[str, Any]:
    sc = store.get_schedule(schedule_id, user_id=user_id_of(user))
    if sc is None:
        raise HTTPException(404, "schedule not found")
    return sc


@app.put("/schedules/{schedule_id}")
def update_schedule(schedule_id: int, body: ScheduleBody, user=Depends(current_user)) -> dict[str, Any]:
    from ..scheduler import validate_cron
    if body.cron and not validate_cron(body.cron):
        raise HTTPException(400, "invalid cron expression")
    sc = store.update_schedule(
        schedule_id, user_id=user_id_of(user), target=body.target, cron=body.cron,
        name=body.name, profile=body.profile, alerts=body.alerts, enabled=body.enabled,
    )
    if sc is None:
        raise HTTPException(404, "schedule not found")
    return sc


@app.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, user=Depends(current_user)) -> dict[str, Any]:
    if not store.delete_schedule(schedule_id, user_id=user_id_of(user)):
        raise HTTPException(404, "schedule not found")
    return {"deleted": schedule_id}


@app.post("/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, user=Depends(current_user)) -> dict[str, Any]:
    sc = store.get_schedule(schedule_id, user_id=user_id_of(user))
    if sc is None:
        raise HTTPException(404, "schedule not found")
    scan_id = await _scheduler.run_schedule(sc)
    return {"schedule_id": schedule_id, "scan_id": scan_id}


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
