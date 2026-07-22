#!/usr/bin/env python3
"""Database migration / bootstrap.

Creates all tables for the configured DATABASE_URL (SQLite by default).
Idempotent — safe to run repeatedly. For real schema evolution in prod, wire in
Alembic; this covers the dev/SQLite path.

    python3 scripts/migrate.py            # create tables
    python3 scripts/migrate.py --reset    # drop + recreate (destructive)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infiltr.db import engine, init_db  # noqa: E402
from infiltr.models import Base  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="drop all tables first (destructive)")
    args = ap.parse_args()

    if args.reset:
        print("[!] dropping all tables …")
        Base.metadata.drop_all(engine)

    print(f"[*] creating tables on {engine.url}")
    init_db()
    tables = ", ".join(sorted(Base.metadata.tables))
    print(f"[+] ready: {tables}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
