# Infiltr

Modular offensive-security orchestration engine. Infiltr wraps 11 industry tools
(nmap, theHarvester, whatweb, feroxbuster, ffuf, gobuster, nikto, sqlmap, wfuzz,
XSStrike, hydra) behind one consistent interface, runs them concurrently against a
target, normalizes their output into structured findings with deterministic
severity scoring, and exposes it all through a CLI, an HTTP API, and a web console.

> **Authorized testing only.** Point Infiltr at systems you own or have explicit
> written permission to test. The bundled Docker lab (DVWA + Juice Shop) is there
> so you never have to aim it anywhere else while developing.

---

## Quick start

```bash
# 1. Bootstrap tools + Python env (apt / brew aware)
bash scripts/setup_dependencies.sh
source .venv/bin/activate

# 2. Bring up the vulnerable lab
docker compose up -d          # DVWA on :8080, Juice Shop on :3000

# 3. Scan
python3 runner.py http://localhost:8080
```

### CLI

```bash
python3 runner.py http://localhost:8080                # run everything
python3 runner.py --modules nmap,whatweb http://host   # pick modules
python3 runner.py --skip-missing http://host           # skip uninstalled tools
python3 runner.py --json out.json http://host          # export results
python3 runner.py --list                               # module registry + install status
```

---

## Architecture

```
infiltr/
  base.py       BaseWrapper + ScanResult / Finding dataclasses
  engine.py     auto-discovery + concurrent orchestration
  config.py     per-module defaults (env-overridable)
  utils.py      target normalization (scheme/host/port/url)
  modules/      one wrapper per tool (drop-in auto-registered)
runner.py       CLI
frontend/       web console (index.html + styles.css + app.js)
scripts/        setup + migrations
tests/          per-module integration tests
```

Every wrapper subclasses `BaseWrapper` and implements three things:

```python
class MyToolWrapper(BaseWrapper):
    MODULE_NAME = "mytool"
    CATEGORY = "web"          # recon | web | auth | misc
    TOOL_BIN = "mytool"       # checked with shutil.which

    def build_command(self, target): ...      # -> list[str]
    def parse_output(self, out, err, rc): ...  # -> list[Finding]
```

The engine discovers it automatically — no registration wiring. `run()` handles
execution, timeouts, error capture, and severity roll-up for you.

### Severity model

Findings carry a deterministic `severity` (`info` → `low` → `medium` → `high` →
`critical`) assigned by the wrapper/engine — never by a language model. The
Phase 8 AI layer only *annotates* and *explains*; it never changes a score.

---

## Roadmap

Infiltr is built in phases (see `Road Map`). Highlights:

- **0–1** Foundation + real execution against the lab
- **2** SQLAlchemy persistence
- **3–4** FastAPI backend + live web console (SSE)
- **5** Deep per-tool parsing + severity
- **6** Reusable scan profiles
- **7** PDF / HTML / Markdown reporting
- **8** AI insight layer (Flint)
- **9** Auth + multi-tenancy
- **10** Plugin/module registry
- **11** Scheduler + continuous monitoring
- **12** Hardening + production readiness

---

## Configuration

Defaults live in `infiltr/config.py` and are overridable via environment:

| Env var             | Purpose                          |
|---------------------|----------------------------------|
| `INFILTR_TIMEOUT`   | per-module timeout (s)           |
| `INFILTR_WORDLIST`  | default fuzzing wordlist         |
| `INFILTR_USERLIST`  | hydra username list              |
| `INFILTR_PASSLIST`  | hydra password list              |
| `INFILTR_THREADS`   | default thread count             |
| `INFILTR_XSSTRIKE`  | path to `xsstrike.py`            |

## Tests

```bash
pip install pytest
pytest -q
```

Integration tests assert every wrapper returns a non-`ERROR` status against the
lab (skipped automatically when a tool isn't installed).
