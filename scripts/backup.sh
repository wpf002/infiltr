#!/usr/bin/env bash
# Postgres backup for Infiltr with rotation.
#
#   ./scripts/backup.sh                      # dump the saas-compose Postgres
#   BACKUP_DIR=/data/backups ./scripts/backup.sh
#   PG_CONTAINER=infiltr-postgres-1 ./scripts/backup.sh
#   DATABASE_URL=postgresql://user:pass@host:5432/db ./scripts/backup.sh   # direct
#
# Keeps the last $KEEP dumps (default 14). Run from cron/systemd-timer, e.g. daily:
#   0 3 * * *  cd /opt/infiltr && ./scripts/backup.sh >> /var/log/infiltr-backup.log 2>&1
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP="${KEEP:-14}"
PG_CONTAINER="${PG_CONTAINER:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
OUT="$BACKUP_DIR/infiltr-${STAMP}.sql.gz"

echo "[backup] -> $OUT"
if [ -n "${DATABASE_URL:-}" ]; then
  # direct connection (strip SQLAlchemy driver suffix like +psycopg)
  URL="$(printf '%s' "$DATABASE_URL" | sed 's/+[a-z0-9]*:\/\//:\/\//')"
  pg_dump "$URL" | gzip > "$OUT"
else
  # via the compose Postgres container
  if [ -z "$PG_CONTAINER" ]; then
    PG_CONTAINER="$(docker ps --filter 'name=postgres' --format '{{.Names}}' | head -1)"
  fi
  [ -n "$PG_CONTAINER" ] || { echo "[backup] no Postgres container found; set PG_CONTAINER or DATABASE_URL" >&2; exit 1; }
  docker exec "$PG_CONTAINER" pg_dump -U "${POSTGRES_USER:-infiltr}" "${POSTGRES_DB:-infiltr}" | gzip > "$OUT"
fi

SIZE="$(du -h "$OUT" | cut -f1)"
echo "[backup] wrote $SIZE"

# rotation: keep the newest $KEEP
COUNT="$(ls -1 "$BACKUP_DIR"/infiltr-*.sql.gz 2>/dev/null | wc -l | tr -d ' ')"
if [ "$COUNT" -gt "$KEEP" ]; then
  ls -1t "$BACKUP_DIR"/infiltr-*.sql.gz | tail -n +"$((KEEP + 1))" | while read -r old; do
    echo "[backup] pruning $old"
    rm -f "$old"
  done
fi
echo "[backup] done ($COUNT dump(s) retained, keeping $KEEP)"
