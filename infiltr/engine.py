"""Discovery and orchestration of tool wrappers."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable

from . import config
from .base import BaseWrapper, ScanResult

_registry: dict[str, type[BaseWrapper]] = {}


def discover(force: bool = False) -> dict[str, type[BaseWrapper]]:
    """Import every module under infiltr.modules and register BaseWrapper subclasses."""
    global _registry
    if _registry and not force:
        return _registry

    registry: dict[str, type[BaseWrapper]] = {}
    from . import modules as modules_pkg  # local import to avoid cycles

    for mod_info in pkgutil.iter_modules(modules_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{modules_pkg.__name__}.{mod_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseWrapper)
                and obj is not BaseWrapper
                and obj.__module__ == module.__name__
            ):
                registry[obj.MODULE_NAME] = obj

    _registry = dict(sorted(registry.items()))
    return _registry


def available_modules() -> dict[str, type[BaseWrapper]]:
    return discover()


def module_status() -> list[dict[str, Any]]:
    """Report install status for every registered module."""
    out = []
    for name, cls in discover().items():
        out.append(
            {
                "name": name,
                "category": cls.CATEGORY,
                "tool": cls.TOOL_BIN,
                "description": cls.DESCRIPTION,
                "installed": cls.is_installed(),
            }
        )
    return out


class Engine:
    """Runs a selected set of modules against a target."""

    def __init__(
        self,
        modules: Iterable[str] | None = None,
        options: dict[str, dict[str, Any]] | None = None,
        max_workers: int = 4,
        skip_missing: bool = False,
    ):
        self.registry = discover()
        self.options = options or {}
        self.max_workers = max_workers
        self.skip_missing = skip_missing
        if modules:
            self.selected = [m for m in modules if m in self.registry]
            self.unknown = [m for m in modules if m not in self.registry]
        else:
            self.selected = list(self.registry.keys())
            self.unknown = []

    def _instantiate(self, name: str) -> BaseWrapper:
        cls = self.registry[name]
        opts = config.for_module(name, self.options.get(name))
        return cls(options=opts)

    def run(
        self,
        target: str,
        on_result: Callable[[ScanResult], None] | None = None,
    ) -> list[ScanResult]:
        """Execute selected modules concurrently, returning results in stable order."""
        wrappers = {}
        for name in self.selected:
            cls = self.registry[name]
            if self.skip_missing and not cls.is_installed():
                continue
            wrappers[name] = self._instantiate(name)

        results: dict[str, ScanResult] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(w.run, target): name for name, w in wrappers.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    res = fut.result()
                except Exception as exc:  # noqa: BLE001
                    res = ScanResult(
                        module=name,
                        category=self.registry[name].CATEGORY,
                        target=target,
                        status="ERROR",
                        error=f"engine caught: {exc}",
                    )
                results[name] = res
                if on_result:
                    on_result(res)

        return [results[n] for n in self.selected if n in results]
