"""Discovery and orchestration of tool wrappers."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable

from . import config
from .base import BaseWrapper, ScanResult

_registry: dict[str, type[BaseWrapper]] = {}
_invalid: dict[str, list[str]] = {}   # class name -> validation errors


def discover(force: bool = False) -> dict[str, type[BaseWrapper]]:
    """Import every module under infiltr.modules and register valid BaseWrapper subclasses.

    Wrappers failing validate() are skipped (recorded in invalid_modules()) so a
    broken drop-in can't crash the whole registry.
    """
    global _registry, _invalid
    if _registry and not force:
        return _registry

    registry: dict[str, type[BaseWrapper]] = {}
    invalid: dict[str, list[str]] = {}
    from . import modules as modules_pkg  # local import to avoid cycles

    for mod_info in pkgutil.iter_modules(modules_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{modules_pkg.__name__}.{mod_info.name}")
        except Exception as exc:  # noqa: BLE001 — a broken file shouldn't kill discovery
            invalid[mod_info.name] = [f"import failed: {exc}"]
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseWrapper)
                and obj is not BaseWrapper
                and obj.__module__ == module.__name__
            ):
                errors = obj.validate()
                if errors:
                    invalid[obj.__name__] = errors
                    continue
                registry[obj.MODULE_NAME] = obj

    _registry = dict(sorted(registry.items()))
    _invalid = invalid
    return _registry


def reload() -> dict[str, type[BaseWrapper]]:
    """Hot-reload: re-import the modules package and rebuild the registry."""
    import importlib as _il
    from . import modules as modules_pkg
    for mod_info in pkgutil.iter_modules(modules_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        name = f"{modules_pkg.__name__}.{mod_info.name}"
        if name in sys.modules:
            try:
                _il.reload(sys.modules[name])
            except Exception:  # noqa: BLE001
                pass
    return discover(force=True)


def invalid_modules() -> dict[str, list[str]]:
    discover()
    return dict(_invalid)


def manifests() -> list[dict]:
    return [cls.manifest() for cls in discover().values()]


def available_modules() -> dict[str, type[BaseWrapper]]:
    return discover()


def module_status() -> list[dict[str, Any]]:
    """Report the full manifest (incl. install status) for every registered module."""
    return [cls.manifest() for cls in discover().values()]


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
