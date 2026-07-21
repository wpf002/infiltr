#!/usr/bin/env bash
# Infiltr — environment bootstrap.
# Installs the Python deps, the scan tools, and the XSStrike clone.
# Supports apt (Debian/Kali/Ubuntu) and brew (macOS). Re-runnable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }

# ---- package manager -------------------------------------------------
PM=""
if command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v brew >/dev/null 2>&1; then PM="brew"
else warn "no apt/brew found — install tools manually"; fi

apt_pkgs=(nmap nikto whatweb hydra sqlmap wfuzz ffuf gobuster feroxbuster theharvester seclists python3-pip python3-venv)
brew_pkgs=(nmap nikto hydra sqlmap ffuf gobuster feroxbuster)

install_tools() {
  case "$PM" in
    apt)
      log "installing tools via apt (sudo)"
      sudo apt-get update -y
      sudo apt-get install -y "${apt_pkgs[@]}" || warn "some apt packages failed"
      ;;
    brew)
      log "installing tools via brew"
      brew install "${brew_pkgs[@]}" || warn "some brew formulae failed"
      warn "whatweb / nikto / wfuzz / theHarvester: install manually on macOS if needed"
      ;;
    *)
      warn "skipping tool install"
      ;;
  esac
}

# ---- python env ------------------------------------------------------
setup_python() {
  log "creating virtualenv (.venv)"
  python3 -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install --quiet --upgrade pip
  pip install --quiet -r requirements.txt
  ok "python deps installed"
}

# ---- xsstrike clone --------------------------------------------------
setup_xsstrike() {
  local dest="${INFILTR_XSSTRIKE_DIR:-$HOME/tools/XSStrike}"
  if [ -d "$dest/.git" ]; then
    log "XSStrike already cloned at $dest — pulling"
    git -C "$dest" pull --quiet || warn "pull failed"
  else
    log "cloning XSStrike -> $dest"
    mkdir -p "$(dirname "$dest")"
    git clone --depth 1 https://github.com/s0md3v/XSStrike.git "$dest"
  fi
  if [ -f "$dest/requirements.txt" ]; then
    pip install --quiet -r "$dest/requirements.txt" || warn "XSStrike deps failed"
  fi
  ok "XSStrike ready — export INFILTR_XSSTRIKE=$dest/xsstrike.py"
}

# ---- wordlists -------------------------------------------------------
check_wordlists() {
  local wl="/usr/share/wordlists/dirb/common.txt"
  if [ -f "$wl" ]; then ok "wordlists present"; else
    warn "default wordlist missing ($wl) — install seclists or set INFILTR_WORDLIST"
  fi
}

main() {
  log "Infiltr setup starting (pkg manager: ${PM:-none})"
  install_tools
  setup_python
  setup_xsstrike
  check_wordlists
  echo
  ok "Setup complete."
  echo "  Activate:  source .venv/bin/activate"
  echo "  Lab up:    docker compose up -d"
  echo "  Scan:      python3 runner.py http://localhost:8080"
}

main "$@"
