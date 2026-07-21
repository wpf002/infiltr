"""Persistence layer: turn in-memory ScanResults into DB rows and query them back."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select, func, desc

from .base import ScanResult, severity_rank, SEVERITY_ORDER
from .db import session_scope, init_db
from .models import ScanRun, ModuleResult, Finding


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
