"""Persistence layer: turn in-memory ScanResults into DB rows and query them back."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select, func, desc

from .base import ScanResult, severity_rank, SEVERITY_ORDER
from .db import session_scope, init_db
from .models import ScanRun, ModuleResult, Finding, Profile, Schedule


def save_scan(
    target: str,
    results: Iterable[ScanResult],
    profile: str | None = None,
    duration: float = 0.0,
    user_id: int | None = None,
    started_at: datetime | None = None,
) -> int:
    """Persist a completed scan; returns the new scan id."""
    init_db()
    results = list(results)
    with session_scope() as s:
        run = ScanRun(
            target=target,
            profile=profile,
            started_at=started_at or datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration=round(duration, 2),
            module_count=len(results),
            status="completed",
            user_id=user_id,
        )
        s.add(run)
        s.flush()  # assign run.id

        top = "info"
        finding_total = 0
        for res in results:
            mr = ModuleResult(
                scan_id=run.id,
                module=res.module,
                category=res.category,
                status=res.status,
                severity=res.severity,
                duration=res.duration,
                returncode=res.returncode,
                summary=res.summary,
                command=res.command,
                raw_output=res.raw_output or "",
                error=res.error,
            )
            s.add(mr)
            s.flush()
            for f in res.findings:
                finding_total += 1
                s.add(
                    Finding(
                        scan_id=run.id,
                        module_result_id=mr.id,
                        module=res.module,
                        type=f.type,
                        name=f.name,
                        value=f.value,
                        detail=f.detail,
                        severity=f.severity,
                        meta=f.metadata or {},
                    )
                )
            if severity_rank(res.severity) > severity_rank(top):
                top = res.severity

        run.finding_count = finding_total
        run.top_severity = top
        return run.id


def start_scan_run(
    target: str,
    module_names: list[str],
    profile: str | None = None,
    user_id: int | None = None,
) -> int:
    """Create a ScanRun row in the 'running' state; returns its id for live polling."""
    init_db()
    with session_scope() as s:
        run = ScanRun(
            target=target,
            profile=profile,
            started_at=datetime.now(timezone.utc),
            module_count=len(module_names),
            status="running",
            user_id=user_id,
        )
        s.add(run)
        s.flush()
        return run.id


def record_module_result(scan_id: int, res: ScanResult) -> None:
    """Insert one module's result + findings into a running scan and update aggregates."""
    init_db()
    with session_scope() as s:
        run = s.get(ScanRun, scan_id)
        if run is None:
            return
        mr = ModuleResult(
            scan_id=scan_id,
            module=res.module,
            category=res.category,
            status=res.status,
            severity=res.severity,
            duration=res.duration,
            returncode=res.returncode,
            summary=res.summary,
            command=res.command,
            raw_output=res.raw_output or "",
            error=res.error,
        )
        s.add(mr)
        s.flush()
        for f in res.findings:
            s.add(
                Finding(
                    scan_id=scan_id,
                    module_result_id=mr.id,
                    module=res.module,
                    type=f.type,
                    name=f.name,
                    value=f.value,
                    detail=f.detail,
                    severity=f.severity,
                    meta=f.metadata or {},
                )
            )
        run.finding_count = (run.finding_count or 0) + len(res.findings)
        if severity_rank(res.severity) > severity_rank(run.top_severity):
            run.top_severity = res.severity


def finalize_scan_run(scan_id: int, duration: float, status: str = "completed") -> None:
    init_db()
    with session_scope() as s:
        run = s.get(ScanRun, scan_id)
        if run is None:
            return
        run.finished_at = datetime.now(timezone.utc)
        run.duration = round(duration, 2)
        run.status = status


def list_scans(limit: int = 50, user_id: int | None = None) -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        stmt = select(ScanRun).order_by(desc(ScanRun.id)).limit(limit)
        if user_id is not None:
            stmt = stmt.where(ScanRun.user_id == user_id)
        return [r.to_dict() for r in s.scalars(stmt).all()]


def get_scan(scan_id: int, user_id: int | None = None) -> dict[str, Any] | None:
    init_db()
    with session_scope() as s:
        run = s.get(ScanRun, scan_id)
        if run is None or (user_id is not None and run.user_id != user_id):
            return None
        return run.to_dict(include_results=True)


def delete_scan(scan_id: int, user_id: int | None = None) -> bool:
    init_db()
    with session_scope() as s:
        run = s.get(ScanRun, scan_id)
        if run is None or (user_id is not None and run.user_id != user_id):
            return False
        s.delete(run)
        return True


def scan_findings(scan_id: int) -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
        return [f.to_dict() for f in s.scalars(stmt).all()]


def mark_false_positives(scan_id: int, items: list[dict[str, Any]]) -> int:
    """Set false_positive=True on findings matching (module, name). Returns count."""
    init_db()
    if not items:
        return 0
    pairs = {(i.get("module"), i.get("name")) for i in items}
    n = 0
    with session_scope() as s:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        for f in s.scalars(stmt).all():
            if (f.module, f.name) in pairs:
                f.false_positive = True
                n += 1
    return n


def severity_histogram(scan_id: int) -> dict[str, int]:
    """Count findings per severity for a scan."""
    init_db()
    hist = {sev: 0 for sev in SEVERITY_ORDER}
    with session_scope() as s:
        rows = s.execute(
            select(Finding.severity, func.count())
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        ).all()
        for sev, count in rows:
            hist[sev] = count
    return hist


# ---- profiles ---------------------------------------------------------
def list_profiles(user_id: int | None = None) -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        stmt = select(Profile).order_by(Profile.id)
        if user_id is not None:
            stmt = stmt.where(Profile.user_id == user_id)
        return [p.to_dict() for p in s.scalars(stmt).all()]


def get_profile(profile_id: int, user_id: int | None = None) -> dict[str, Any] | None:
    init_db()
    with session_scope() as s:
        p = s.get(Profile, profile_id)
        if p is None or (user_id is not None and p.user_id != user_id):
            return None
        return p.to_dict()


def get_profile_by_name(name: str, user_id: int | None = None) -> dict[str, Any] | None:
    init_db()
    with session_scope() as s:
        stmt = select(Profile).where(Profile.name == name)
        if user_id is not None:
            stmt = stmt.where(Profile.user_id == user_id)
        p = s.scalars(stmt).first()
        return p.to_dict() if p else None


def create_profile(
    name: str,
    modules: list[str],
    description: str = "",
    target: str | None = None,
    options: dict | None = None,
    user_id: int | None = None,
) -> dict[str, Any]:
    init_db()
    with session_scope() as s:
        p = Profile(
            name=name,
            description=description,
            target=target,
            modules=modules or [],
            options=options or {},
            user_id=user_id,
        )
        s.add(p)
        s.flush()
        return p.to_dict()


def update_profile(profile_id: int, user_id: int | None = None, **fields) -> dict[str, Any] | None:
    init_db()
    allowed = {"name", "description", "target", "modules", "options"}
    with session_scope() as s:
        p = s.get(Profile, profile_id)
        if p is None or (user_id is not None and p.user_id != user_id):
            return None
        for k, v in fields.items():
            if k in allowed and v is not None:
                setattr(p, k, v)
        s.flush()
        return p.to_dict()


def delete_profile(profile_id: int, user_id: int | None = None) -> bool:
    init_db()
    with session_scope() as s:
        p = s.get(Profile, profile_id)
        if p is None or (user_id is not None and p.user_id != user_id):
            return False
        s.delete(p)
        return True


def _finding_key(f) -> tuple:
    return (f.module, f.type, f.name, f.value)


def apply_delta(scan_id: int) -> dict[str, Any]:
    """Flag findings new since the previous scan of the same target. Returns a summary."""
    init_db()
    with session_scope() as s:
        run = s.get(ScanRun, scan_id)
        if run is None:
            return {"new_count": 0, "previous_scan_id": None, "new_modules": []}
        prev_stmt = (
            select(ScanRun)
            .where(ScanRun.target == run.target, ScanRun.id < scan_id, ScanRun.status == "completed")
            .order_by(desc(ScanRun.id)).limit(1)
        )
        if run.user_id is not None:
            prev_stmt = prev_stmt.where(ScanRun.user_id == run.user_id)
        prev = s.scalars(prev_stmt).first()

        cur_findings = s.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
        if prev is None:
            # first-ever scan of this target: nothing is "new"
            return {"new_count": 0, "previous_scan_id": None, "new_modules": []}

        prev_keys = {
            _finding_key(f)
            for f in s.scalars(select(Finding).where(Finding.scan_id == prev.id)).all()
        }
        new_modules: set[str] = set()
        new_count = 0
        for f in cur_findings:
            if _finding_key(f) not in prev_keys:
                f.is_new = True
                new_count += 1
                new_modules.add(f.module)
        return {"new_count": new_count, "previous_scan_id": prev.id, "new_modules": sorted(new_modules)}


def scan_delta(scan_id: int) -> dict[str, Any]:
    """New + resolved findings vs the previous scan of the same target."""
    init_db()
    with session_scope() as s:
        run = s.get(ScanRun, scan_id)
        if run is None:
            return {"new": [], "resolved": [], "previous_scan_id": None}
        prev_stmt = (
            select(ScanRun)
            .where(ScanRun.target == run.target, ScanRun.id < scan_id, ScanRun.status == "completed")
            .order_by(desc(ScanRun.id)).limit(1)
        )
        if run.user_id is not None:
            prev_stmt = prev_stmt.where(ScanRun.user_id == run.user_id)
        prev = s.scalars(prev_stmt).first()

        cur = s.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
        cur_map = {_finding_key(f): f for f in cur}
        prev_findings = (
            s.scalars(select(Finding).where(Finding.scan_id == prev.id)).all() if prev else []
        )
        prev_map = {_finding_key(f): f for f in prev_findings}

        new = [f.to_dict() for k, f in cur_map.items() if k not in prev_map]
        resolved = [f.to_dict() for k, f in prev_map.items() if k not in cur_map]
        return {"new": new, "resolved": resolved, "previous_scan_id": prev.id if prev else None}


def target_trend(target: str, limit: int = 30, user_id: int | None = None) -> list[dict[str, Any]]:
    """Chronological findings-count series for a target."""
    init_db()
    with session_scope() as s:
        stmt = (
            select(ScanRun)
            .where(ScanRun.target == target, ScanRun.status == "completed")
            .order_by(ScanRun.id).limit(limit)
        )
        if user_id is not None:
            stmt = stmt.where(ScanRun.user_id == user_id)
        return [
            {
                "scan_id": r.id,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finding_count": r.finding_count,
                "top_severity": r.top_severity,
            }
            for r in s.scalars(stmt).all()
        ]


# ---- schedules --------------------------------------------------------
def create_schedule(target, cron, name="", profile=None, alerts=None, user_id=None) -> dict[str, Any]:
    init_db()
    with session_scope() as s:
        sc = Schedule(target=target, cron=cron, name=name, profile=profile,
                      alerts=alerts or {}, user_id=user_id)
        s.add(sc)
        s.flush()
        return sc.to_dict()


def list_schedules(user_id: int | None = None, only_enabled: bool = False) -> list[dict[str, Any]]:
    init_db()
    with session_scope() as s:
        stmt = select(Schedule).order_by(Schedule.id)
        if user_id is not None:
            stmt = stmt.where(Schedule.user_id == user_id)
        if only_enabled:
            stmt = stmt.where(Schedule.enabled == True)  # noqa: E712
        return [x.to_dict() for x in s.scalars(stmt).all()]


def get_schedule(schedule_id: int, user_id: int | None = None) -> dict[str, Any] | None:
    init_db()
    with session_scope() as s:
        sc = s.get(Schedule, schedule_id)
        if sc is None or (user_id is not None and sc.user_id != user_id):
            return None
        return sc.to_dict()


def update_schedule(schedule_id: int, user_id: int | None = None, **fields) -> dict[str, Any] | None:
    init_db()
    allowed = {"name", "target", "profile", "cron", "enabled", "alerts"}
    with session_scope() as s:
        sc = s.get(Schedule, schedule_id)
        if sc is None or (user_id is not None and sc.user_id != user_id):
            return None
        for k, v in fields.items():
            if k in allowed and v is not None:
                setattr(sc, k, v)
        s.flush()
        return sc.to_dict()


def delete_schedule(schedule_id: int, user_id: int | None = None) -> bool:
    init_db()
    with session_scope() as s:
        sc = s.get(Schedule, schedule_id)
        if sc is None or (user_id is not None and sc.user_id != user_id):
            return False
        s.delete(sc)
        return True


def mark_schedule_run(schedule_id: int, scan_id: int) -> None:
    init_db()
    with session_scope() as s:
        sc = s.get(Schedule, schedule_id)
        if sc is not None:
            sc.last_run = datetime.now(timezone.utc)
            sc.last_scan_id = scan_id


def previous_scan_for_target(target: str, before_id: int, user_id: int | None = None):
    """Most recent completed scan of the same target before `before_id` (delta detection)."""
    init_db()
    with session_scope() as s:
        stmt = (
            select(ScanRun)
            .where(ScanRun.target == target, ScanRun.id < before_id, ScanRun.status == "completed")
            .order_by(desc(ScanRun.id))
            .limit(1)
        )
        if user_id is not None:
            stmt = stmt.where(ScanRun.user_id == user_id)
        run = s.scalars(stmt).first()
        return run.to_dict(include_results=True) if run else None
