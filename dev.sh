#!/usr/bin/env bash
# Start the Infiltr API (which also serves the web console at /).
#   ./dev.sh            -> http://localhost:8000  (console + API, single origin)
#   PORT=9000 ./dev.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PORT="${PORT:-8000}"
HOST="${HOST:-127.0.0.1}"

# activate venv if present
if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# --- full stack on by default -----------------------------------------
# background scheduler + a signing key so every subsystem is live locally.
export INFILTR_SCHEDULER="${INFILTR_SCHEDULER:-1}"
if [ -z "${INFILTR_SECRET_KEY:-}" ]; then
  export INFILTR_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
fi
# Auth endpoints are always available; enforcement is opt-in (INFILTR_AUTH=1).
export INFILTR_AUTH="${INFILTR_AUTH:-0}"

# HTTPS-only mode when a cert/key pair is provided
TLS_ARGS=()
SCHEME="http"
if [ -n "${INFILTR_TLS_CERT:-}" ] && [ -n "${INFILTR_TLS_KEY:-}" ]; then
  TLS_ARGS=(--ssl-certfile "$INFILTR_TLS_CERT" --ssl-keyfile "$INFILTR_TLS_KEY")
  SCHEME="https"
fi

echo "[*] Infiltr console + API -> ${SCHEME}://${HOST}:${PORT}/"
echo "[*] API docs             -> ${SCHEME}://${HOST}:${PORT}/docs"
echo "[*] scheduler=${INFILTR_SCHEDULER}  auth_enforced=${INFILTR_AUTH}"
PY="${PYTHON:-python3}"
# ${arr[@]+...} guards empty-array expansion under `set -u` on bash 3.2 (macOS)
exec "$PY" -m uvicorn infiltr.api.app:app --host "$HOST" --port "$PORT" --reload ${TLS_ARGS[@]+"${TLS_ARGS[@]}"}
