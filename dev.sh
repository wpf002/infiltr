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

# HTTPS-only mode when a cert/key pair is provided
TLS_ARGS=()
SCHEME="http"
if [ -n "${INFILTR_TLS_CERT:-}" ] && [ -n "${INFILTR_TLS_KEY:-}" ]; then
  TLS_ARGS=(--ssl-certfile "$INFILTR_TLS_CERT" --ssl-keyfile "$INFILTR_TLS_KEY")
  SCHEME="https"
fi

echo "[*] Infiltr console + API -> ${SCHEME}://${HOST}:${PORT}/"
echo "[*] API docs             -> ${SCHEME}://${HOST}:${PORT}/docs"
exec uvicorn infiltr.api.app:app --host "$HOST" --port "$PORT" --reload "${TLS_ARGS[@]}"
