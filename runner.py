#!/usr/bin/env python3
"""Infiltr CLI — orchestrate security tool wrappers against a target.

Usage:
    python3 runner.py http://localhost:8080
    python3 runner.py --modules nmap,whatweb http://target
    python3 runner.py --list
    python3 runner.py --json out.json http://target
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from infiltr.engine import Engine, module_status
from infiltr.base import PASS, ERROR, SEVERITY_ORDER, severity_rank

# ---- ANSI ----
_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m", "grey": "\033[90m",
}
_SEV_COLOR = {
    "critical": "magenta", "high": "red", "medium": "yellow",
    "low": "cyan", "info": "grey",
}


def c(txt: str, color: str, enable: bool = True) -> str:
    if not enable:
        return txt
    return f"{_C.get(color, '')}{txt}{_C['reset']}"


def status_badge(status: str, enable: bool) -> str:
    if status == PASS:
        return c(" PASS ", "green", enable)
    if status == ERROR:
        return c(" ERROR", "red", enable)
    return c(f" {status}", "yellow", enable)


def print_banner(target: str, modules: list[str], enable: bool):
    print(c("\n  ┌─────────────────────────────────────────────┐", "cyan", enable))
    print(c("  │            I N F I L T R                    │", "cyan", enable) + c(f"  {len(modules)} modules", "dim", enable))
    print(c("  └─────────────────────────────────────────────┘", "cyan", enable))
    print(f"  {c('target', 'dim', enable)}  {c(target, 'bold', enable)}")
    print(f"  {c('modules', 'dim', enable)} {', '.join(modules)}\n")


def cmd_list(enable: bool) -> int:
    print(c("\n  Registered modules\n", "bold", enable))
    for m in module_status():
        badge = c("installed", "green", enable) if m["installed"] else c("missing", "red", enable)
        print(f"  {m['name']:<14} {c(m['category'], 'dim', enable):<10} [{badge}]  {c(m['description'], 'dim', enable)}")
    print()
    return 0


def cmd_history(color: bool, limit: int) -> int:
    from infiltr import store
    scans = store.list_scans(limit=limit)
    if not scans:
        print(c("\n  No scans recorded yet.\n", "dim", color))
        return 0
    print(c("\n  Scan history\n", "bold", color))
    print(f"  {'ID':>4}  {'TARGET':<32} {'STARTED':<20} {'MODS':>4} {'FIND':>4}  SEVERITY")
    for sc in scans:
        sev = sc["top_severity"]
        started = (sc["started_at"] or "")[:19].replace("T", " ")
        print(
            f"  {sc['id']:>4}  {sc['target'][:32]:<32} {started:<20} "
            f"{sc['module_count']:>4} {sc['finding_count']:>4}  "
            f"{c(sev.upper(), _SEV_COLOR.get(sev, 'grey'), color)}"
        )
    print()
    return 0


def cmd_show(color: bool, scan_id: int, json_out: str | None) -> int:
    from infiltr import store
    scan = store.get_scan(scan_id)
    if scan is None:
        print(c(f"\n  No scan with id {scan_id}.\n", "red", color))
        return 1
    if json_out:
        with open(json_out, "w") as fh:
            json.dump(scan, fh, indent=2)
        print(c(f"  scan {scan_id} written to {json_out}\n", "green", color))
        return 0
    print(c(f"\n  Scan #{scan['id']}  ", "bold", color) + c(scan["target"], "cyan", color))
    print(f"  {c('started', 'dim', color)} {scan['started_at']}   {c('duration', 'dim', color)} {scan['duration']}s")
    print(f"  {c('findings', 'dim', color)} {scan['finding_count']}   {c('top', 'dim', color)} "
          f"{c(scan['top_severity'].upper(), _SEV_COLOR.get(scan['top_severity'], 'grey'), color)}\n")
    for r in scan["results"]:
        print(f"  {status_badge(r['status'], color)}  {c(r['module'], 'bold', color):<14} "
              f"{c(r['severity'].upper(), _SEV_COLOR.get(r['severity'], 'grey'), color):<8} {r['summary']}")
        for f in r.get("findings", []):
            print(f"      · [{f['severity']}] {f['name']} {f['value']}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runner.py", description="Infiltr scan orchestrator")
    parser.add_argument("target", nargs="?", help="target URL / host / IP")
    parser.add_argument("--modules", "-m", help="comma-separated module names (default: all)")
    parser.add_argument("--json", "-j", metavar="FILE", help="write results as JSON")
    parser.add_argument("--skip-missing", action="store_true", help="skip uninstalled tools")
    parser.add_argument("--workers", "-w", type=int, default=4, help="concurrent modules")
    parser.add_argument("--list", action="store_true", help="list modules and exit")
    parser.add_argument("--history", action="store_true", help="show recent scans and exit")
    parser.add_argument("--scan", type=int, metavar="ID", help="show a stored scan by id")
    parser.add_argument("--limit", type=int, default=50, help="history limit")
    parser.add_argument("--no-save", action="store_true", help="do not persist to the database")
    parser.add_argument("--profile", "-p", help="named scan profile")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args(argv)

    color = sys.stdout.isatty() and not args.no_color

    if args.list:
        return cmd_list(color)
    if args.history:
        return cmd_history(color, args.limit)
    if args.scan is not None:
        return cmd_show(color, args.scan, args.json)

    if not args.target:
        parser.error("target is required (or use --list / --history / --scan)")

    modules = [m.strip() for m in args.modules.split(",")] if args.modules else None
    engine = Engine(modules=modules, max_workers=args.workers, skip_missing=args.skip_missing)

    if engine.unknown:
        print(c(f"  unknown modules ignored: {', '.join(engine.unknown)}", "yellow", color))

    selected = engine.selected
    print_banner(args.target, selected, color)

    done = {"n": 0}
    total = len(selected)

    def on_result(res):
        done["n"] += 1
        badge = status_badge(res.status, color)
        sev = res.severity
        sev_txt = c(sev.upper(), _SEV_COLOR.get(sev, "grey"), color)
        line = (
            f"  [{done['n']:>2}/{total}] {badge}  "
            f"{c(res.module, 'bold', color):<14} "
            f"{res.duration:>6.1f}s  {sev_txt:<8}  {res.summary}"
        )
        print(line)
        if res.error:
            print(f"           {c('↳ ' + res.error, 'red', color)}")

    started_at = datetime.now(timezone.utc)
    t0 = time.monotonic()
    results = engine.run(args.target, on_result=on_result)
    elapsed = time.monotonic() - t0

    # summary
    passed = sum(1 for r in results if r.status == PASS)
    errored = sum(1 for r in results if r.status == ERROR)
    total_findings = sum(len(r.findings) for r in results)
    top_sev = "info"
    for r in results:
        if severity_rank(r.severity) > severity_rank(top_sev):
            top_sev = r.severity

    print(c("\n  ─── summary ───────────────────────────────────", "cyan", color))
    print(f"  {c('modules', 'dim', color)}   {passed} passed, {errored} error")
    print(f"  {c('findings', 'dim', color)}  {total_findings}")
    print(f"  {c('highest', 'dim', color)}   {c(top_sev.upper(), _SEV_COLOR.get(top_sev, 'grey'), color)}")
    print(f"  {c('elapsed', 'dim', color)}   {elapsed:.1f}s")

    scan_id = None
    if not args.no_save:
        try:
            from infiltr import store
            scan_id = store.save_scan(
                args.target, results, profile=args.profile,
                duration=elapsed, started_at=started_at,
            )
            print(f"  {c('scan id', 'dim', color)}   {c('#' + str(scan_id), 'green', color)}"
                  f"   {c('(runner.py --scan ' + str(scan_id) + ')', 'dim', color)}")
        except Exception as exc:  # noqa: BLE001
            print(c(f"  [!] persistence failed: {exc}", "yellow", color))
    print()

    if args.json:
        if scan_id is not None:
            from infiltr import store
            payload = store.get_scan(scan_id)
        else:
            payload = {
                "target": args.target,
                "elapsed": round(elapsed, 2),
                "results": [r.to_dict() for r in results],
            }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(c(f"  results written to {args.json}\n", "green", color))

    return 0 if errored == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
