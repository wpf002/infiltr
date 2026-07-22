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

echo "[*] Infiltr console + API -> http://${HOST}:${PORT}/"
echo "[*] API docs             -> http://${HOST}:${PORT}/docs"
exec uvicorn infiltr.api.app:app --host "$HOST" --port "$PORT" --reload
