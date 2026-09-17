#!/usr/bin/env bash
# Restore an Infiltr Postgres dump written by backup.sh.
#
#   ./scripts/restore.sh backups/infiltr-20260917T030000Z.sql.gz
#   PG_CONTAINER=infiltr-postgres-1 ./scripts/restore.sh <dump.sql.gz>
#   DATABASE_URL=postgresql://user:pass@host:5432/db ./scripts/restore.sh <dump.sql.gz>
#
# DESTRUCTIVE: overwrites current data. Requires typing YES.
set -euo pipefail

DUMP="${1:-}"
[ -n "$DUMP" ] && [ -f "$DUMP" ] || { echo "usage: restore.sh <dump.sql.gz>" >&2; exit 1; }

echo "This will OVERWRITE the current Infiltr database with: $DUMP"
printf "Type YES to continue: "
read -r confirm
[ "$confirm" = "YES" ] || { echo "aborted"; exit 1; }

decompress() { gzip -dc "$DUMP"; }

if [ -n "${DATABASE_URL:-}" ]; then
  URL="$(printf '%s' "$DATABASE_URL" | sed 's/+[a-z0-9]*:\/\//:\/\//')"
  decompress | psql "$URL"
else
  PG_CONTAINER="${PG_CONTAINER:-$(docker ps --filter 'name=postgres' --format '{{.Names}}' | head -1)}"
  [ -n "$PG_CONTAINER" ] || { echo "no Postgres container; set PG_CONTAINER or DATABASE_URL" >&2; exit 1; }
  decompress | docker exec -i "$PG_CONTAINER" psql -U "${POSTGRES_USER:-infiltr}" "${POSTGRES_DB:-infiltr}"
fi
echo "[restore] done"
