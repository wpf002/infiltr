"""SQLAlchemy ORM models: ScanRun -> ModuleResult -> Finding."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Dict, List

from sqlalchemy import String, Integer, Float, Text, ForeignKey, JSON, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    profile: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    module_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    top_severity: Mapped[str] = mapped_column(String(16), default="info")
    status: Mapped[str] = mapped_column(String(16), default="running")
    # user scoping (Phase 9 attaches the FK + relationship); nullable until auth exists
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)

    results: Mapped[List["ModuleResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ModuleResult.id"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def to_dict(self, include_results: bool = False) -> dict[str, Any]:
        d = {
            "id": self.id,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration": self.duration,
            "module_count": self.module_count,
            "finding_count": self.finding_count,
            "top_severity": self.top_severity,
            "status": self.status,
            "user_id": self.user_id,
        }
        if include_results:
            d["results"] = [r.to_dict(include_findings=True) for r in self.results]
        return d


class ModuleResult(Base):
    __tablename__ = "module_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(32), default="misc")
    status: Mapped[str] = mapped_column(String(16), default="PASS")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    returncode: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    command: Mapped[str] = mapped_column(Text, default="")
    raw_output: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["ScanRun"] = relationship(back_populates="results")
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="module_result", cascade="all, delete-orphan", order_by="Finding.id"
    )

    def to_dict(self, include_findings: bool = False) -> dict[str, Any]:
        d = {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "duration": self.duration,
            "returncode": self.returncode,
            "summary": self.summary,
            "command": self.command,
            "error": self.error,
        }
        if include_findings:
            d["findings"] = [f.to_dict() for f in self.findings]
            d["raw_output"] = self.raw_output
        return d


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="operator")  # admin|operator|viewer
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(64), default="")
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "user_id": self.user_id, "name": self.name,
            "prefix": self.prefix, "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
        }


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "user_id": self.user_id, "actor": self.actor,
            "action": self.action, "detail": self.detail, "target": self.target,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Profile(Base):
    """A named, reusable scan configuration (user-defined; built-ins live in code)."""
    __tablename__ = "profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    modules: Mapped[List[str]] = mapped_column(JSON, default=list)
    options: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "modules": self.modules or [],
            "options": self.options or {},
            "builtin": False,
            "user_id": self.user_id,
        }


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    module_result_id: Mapped[int] = mapped_column(
        ForeignKey("module_results.id", ondelete="CASCADE"), index=True
    )
    module: Mapped[str] = mapped_column(String(64), index=True)
    type: Mapped[str] = mapped_column(String(48), default="finding")
    name: Mapped[str] = mapped_column(Text, default="")
    value: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    meta: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    # Phase 8/11 flags
    false_positive: Mapped[bool] = mapped_column(default=False)
    is_new: Mapped[bool] = mapped_column(default=False)

    scan: Mapped["ScanRun"] = relationship(back_populates="findings")
    module_result: Mapped["ModuleResult"] = relationship(back_populates="findings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "module": self.module,
            "type": self.type,
            "name": self.name,
            "value": self.value,
            "detail": self.detail,
            "severity": self.severity,
            "metadata": self.meta or {},
            "false_positive": self.false_positive,
            "is_new": self.is_new,
        }
