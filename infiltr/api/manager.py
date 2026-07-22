"""Background scan manager with live SSE broadcasting.

Runs the (blocking) engine in a worker thread, persists each module result as it
lands, and fans out progress events to any number of SSE subscribers.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from .. import store
from ..engine import Engine


class Job:
    def __init__(self, scan_id: int, total: int):
        self.scan_id = scan_id
        self.total = total
        self.completed = 0
        self.status = "running"
        self.events: list[dict[str, Any]] = []
        self.subscribers: set[asyncio.Queue] = set()
        self.done = asyncio.Event()


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
    ) -> int:
        engine = Engine(modules=modules, options=options, max_workers=workers, skip_missing=skip_missing)
        selected = engine.selected
        scan_id = await asyncio.to_thread(store.start_scan_run, target, selected, profile, user_id)
        job = Job(scan_id, len(selected))
        self.jobs[scan_id] = job
        loop = asyncio.get_running_loop()
        # keep a strong reference so the background task isn't garbage-collected
        task = asyncio.create_task(self._run(job, engine, target, loop))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan_id

    async def _run(self, job: Job, engine: Engine, target: str, loop: asyncio.AbstractEventLoop) -> None:
        t0 = time.monotonic()

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
            await asyncio.to_thread(engine.run, target, on_result)
            status = "completed"
        except Exception as exc:  # noqa: BLE001
            status = "error"
            self._broadcast(job, {"type": "error", "scan_id": job.scan_id, "error": str(exc)})

        await asyncio.to_thread(store.finalize_scan_run, job.scan_id, time.monotonic() - t0, status)
        job.status = status
        self._broadcast(job, {"type": "done", "scan_id": job.scan_id, "status": status})
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
            # scan already finished (or unknown) — nothing live to stream
            yield {"type": "done", "scan_id": scan_id, "status": "completed"}
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


manager = ScanManager()
