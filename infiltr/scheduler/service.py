"""Async scheduler: ticks each minute, runs due schedules, fires delta alerts.

Enabled via INFILTR_SCHEDULER=1 so it stays out of the way in tests/dev. Uses the
same ScanManager as the API, so scheduled scans stream + persist identically.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from .. import store
from .cron import cron_matches
from .alerts import dispatch_alerts


class Scheduler:
    def __init__(self, manager, poll_seconds: int = 60):
        self.manager = manager
        self.poll_seconds = poll_seconds
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_tick_minute: Optional[str] = None

    def start(self) -> None:
        if self._task is None:
            self._running = True
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.tick(datetime.now(timezone.utc))
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(self.poll_seconds)

    async def tick(self, now: datetime) -> list[int]:
        """Run every schedule whose cron matches this minute. Returns triggered scan ids."""
        minute_key = now.strftime("%Y%m%d%H%M")
        if minute_key == self._last_tick_minute:
            return []
        self._last_tick_minute = minute_key

        triggered: list[int] = []
        for sched in store.list_schedules(only_enabled=True):
            if cron_matches(sched["cron"], now):
                scan_id = await self.run_schedule(sched)
                if scan_id is not None:
                    triggered.append(scan_id)
        return triggered

    async def run_schedule(self, sched: dict) -> Optional[int]:
        """Trigger one schedule immediately; wire delta alerts on completion."""
        from ..profiles import resolve_modules, resolve_options
        modules = resolve_modules(sched.get("profile"), None, user_id=sched.get("user_id"))
        scan_id = await self.manager.start_scan(
            target=sched["target"],
            modules=modules or [],
            options=resolve_options(sched.get("profile"), user_id=sched.get("user_id")),
            profile=sched.get("profile"),
            user_id=sched.get("user_id"),
        )
        store.mark_schedule_run(sched["id"], scan_id)

        alerts = sched.get("alerts") or {}
        if alerts:
            asyncio.create_task(self._alert_on_done(scan_id, sched["target"], alerts))
        return scan_id

    async def _alert_on_done(self, scan_id: int, target: str, alerts: dict) -> None:
        job = self.manager.jobs.get(scan_id)
        if job is not None:
            await job.done.wait()
        summary = await asyncio.to_thread(store.apply_delta, scan_id)
        if summary.get("new_count", 0) > 0:
            payload = {"scan_id": scan_id, "target": target, **summary}
            await asyncio.to_thread(dispatch_alerts, alerts, payload)
