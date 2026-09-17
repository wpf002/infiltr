"""Background scan manager with live SSE broadcasting.

Runs the (blocking) engine in a worker thread, persists each module result as it
lands, and fans out progress events to any number of SSE subscribers.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from .. import store
from .. import safety
from .. import shared_state
from ..engine import Engine

MAX_CONCURRENT = int(os.environ.get("INFILTR_MAX_CONCURRENT", "3"))
GLOBAL_MAX = int(os.environ.get("INFILTR_GLOBAL_MAX_CONCURRENT", "20"))


class ConcurrencyError(RuntimeError):
    """Too many concurrent scans for this user."""


class Job:
    def __init__(self, scan_id: int, total: int, engine=None):
        self.scan_id = scan_id
        self.total = total
        self.engine = engine
        self.completed = 0
        self.status = "running"
        self.cancelled = False
        self.events: list[dict[str, Any]] = []
        self.subscribers: set[asyncio.Queue] = set()
        self.done = asyncio.Event()
        self.reservation = None  # shared_state slot handle, released on finalize


class ScanManager:
    def __init__(self) -> None:
        self.jobs: dict[int, Job] = {}
        self._tasks: set[asyncio.Task] = set()

    # ---- lifecycle ----------------------------------------------------
    async def start_scan(
        self,
        target: str,
        modules: list[str],
        options: dict[str, Any] | None = None,
        profile: str | None = None,
        user_id: int | None = None,
        workers: int = 4,
        skip_missing: bool = False,
        auth_headers: dict | None = None,
    ) -> int:
        # hardening: sanitize + enforce scope before anything is created
        target = safety.check_scope(target)

        key = str(user_id) if user_id is not None else "anon"
        # atomically reserve one global + one per-user slot. Cross-node when REDIS_URL
        # is set (all replicas share the cap); in-process counter otherwise.
        reservation, reason = shared_state.reserve(key, MAX_CONCURRENT, GLOBAL_MAX)
        if reservation is None:
            raise ConcurrencyError(reason)
        try:
            engine = Engine(modules=modules, options=options, max_workers=workers,
                            skip_missing=skip_missing, auth_headers=auth_headers)
            selected = engine.selected
            scan_id = await asyncio.to_thread(store.start_scan_run, target, selected, profile, user_id)
        except Exception:
            shared_state.release(reservation)
            raise
        job = Job(scan_id, len(selected), engine=engine)
        job.reservation = reservation
        self.jobs[scan_id] = job
        loop = asyncio.get_running_loop()
        # keep a strong reference so the background task isn't garbage-collected
        task = asyncio.create_task(self._run(job, engine, target, loop))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan_id

    async def drain(self, timeout: float = 25.0) -> None:
        """Graceful shutdown: cancel every live scan and wait briefly for finalize."""
        for job in list(self.jobs.values()):
            if job.status == "running":
                job.cancelled = True
                if job.engine is not None:
                    try:
                        job.engine.cancel()
                    except Exception:  # noqa: BLE001
                        pass
        if self._tasks:
            try:
                await asyncio.wait(set(self._tasks), timeout=timeout)
            except Exception:  # noqa: BLE001
                pass

    def cancel(self, scan_id: int) -> bool:
        """Stop a running scan: skip queued modules, kill running ones."""
        job = self.jobs.get(scan_id)
        if job is None or job.status != "running":
            return False
        job.cancelled = True
        if job.engine is not None:
            job.engine.cancel()
        return True

    async def _run(self, job: Job, engine: Engine, target: str, loop: asyncio.AbstractEventLoop) -> None:
        t0 = time.monotonic()

        def on_start(name):  # worker thread — module just got a slot
            loop.call_soon_threadsafe(
                self._broadcast, job,
                {"type": "module_start", "scan_id": job.scan_id, "module": name},
            )

        def on_result(res):  # runs in an engine worker thread
            try:
                store.record_module_result(job.scan_id, res)
            except Exception:  # noqa: BLE001
                pass
            job.completed += 1
            evt = {
                "type": "module",
                "scan_id": job.scan_id,
                "completed": job.completed,
                "total": job.total,
                "result": res.to_dict(),
            }
            loop.call_soon_threadsafe(self._broadcast, job, evt)

        try:
            await asyncio.to_thread(engine.run, target, on_result, on_start)
            status = "cancelled" if job.cancelled else "completed"
        except Exception as exc:  # noqa: BLE001
            status = "error"
            self._broadcast(job, {"type": "error", "scan_id": job.scan_id, "error": str(exc)})

        await asyncio.to_thread(store.finalize_scan_run, job.scan_id, time.monotonic() - t0, status)
        # delta detection: flag findings new since the previous scan of this target
        delta = {}
        try:
            delta = await asyncio.to_thread(store.apply_delta, job.scan_id)
        except Exception:  # noqa: BLE001
            pass
        shared_state.release(job.reservation)
        job.reservation = None
        job.status = status
        self._broadcast(job, {"type": "done", "scan_id": job.scan_id, "status": status, "delta": delta})
        job.done.set()

    # ---- pub/sub ------------------------------------------------------
    def _broadcast(self, job: Job, event: dict[str, Any]) -> None:
        job.events.append(event)
        for q in list(job.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self, scan_id: int):
        """Async generator of events for a scan; replays history then streams live."""
        job = self.jobs.get(scan_id)
        if job is None:
            # Not running on this replica. Either it finished, or it's running on
            # another node (multi-tenant/multi-replica). Reconstruct progress from
            # the shared DB so live updates work regardless of which node serves SSE.
            async for evt in self._db_progress(scan_id):
                yield evt
            return
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        # replay what already happened so late subscribers stay consistent
        for evt in job.events:
            await q.put(evt)
        job.subscribers.add(q)
        try:
            if job.status != "running" and job.done.is_set():
                # drain replay then stop
                while not q.empty():
                    yield await q.get()
                return
            while True:
                evt = await q.get()
                yield evt
                if evt.get("type") == "done":
                    return
        finally:
            job.subscribers.discard(q)

    async def _db_progress(self, scan_id: int):
        """Cross-node/late SSE: poll the shared DB and emit module + done events."""
        seen: set[str] = set()
        for _ in range(4000):  # ~1h ceiling at 0.9s
            scan = await asyncio.to_thread(store.get_scan, scan_id)
            if scan is None:
                yield {"type": "done", "scan_id": scan_id, "status": "unknown"}
                return
            for r in scan.get("results", []):
                if r["module"] not in seen:
                    seen.add(r["module"])
                    yield {"type": "module", "scan_id": scan_id,
                           "completed": len(seen), "total": scan.get("module_count", 0),
                           "result": r}
            if scan.get("status") != "running":
                yield {"type": "done", "scan_id": scan_id, "status": scan["status"]}
                return
            await asyncio.sleep(0.9)
        yield {"type": "done", "scan_id": scan_id, "status": "timeout"}


manager = ScanManager()
