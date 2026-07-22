# Writing an Infiltr module

A module is a single Python file in `infiltr/modules/` that subclasses
`BaseWrapper`. Drop it in — the engine auto-discovers, validates, and registers
it. No core files to edit.

## Minimal wrapper

```python
from ..base import BaseWrapper, Finding, SEV_LOW
from ..utils import base_url

class MyToolWrapper(BaseWrapper):
    MODULE_NAME = "mytool"          # unique registry key
    CATEGORY    = "web"            # recon | web | auth | misc
    TOOL_BIN    = "mytool"         # binary checked with shutil.which
    DESCRIPTION = "What it does"
    VERSION     = "1.0"
    OPTIONS_SCHEMA = {              # optional, powers the manifest / UI
        "depth": {"type": "int", "default": 2, "help": "crawl depth"},
    }

    def build_command(self, target: str) -> list[str]:
        return [self.TOOL_BIN, "-u", base_url(target)]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "INTERESTING" in line:
                findings.append(Finding(type="finding", name="hit", value=line.strip(), severity=SEV_LOW))
        return findings
```

## Contract

`BaseWrapper.validate()` enforces (a broken wrapper is skipped, never crashes discovery):

| Requirement | Rule |
|-------------|------|
| `MODULE_NAME` | non-empty, unique |
| `CATEGORY` | one of `recon`, `web`, `auth`, `misc` |
| `TOOL_BIN` | names the executable |
| `build_command()` | overridden, returns `list[str]` |
| `parse_output()` | overridden, returns `list[Finding]` |

`run()` (provided) handles execution, timeouts, error capture, and severity
roll-up — you never call the subprocess yourself.

## Findings & severity

Return `Finding` objects. Severity is **your** deterministic judgment
(`SEV_INFO`→`SEV_CRITICAL`); the AI layer never overrides it. Put structured
extras in `metadata` (status codes, ports, versions).

## Target helpers (`infiltr.utils`)

`normalize_url`, `base_url`, `hostname`, `host_port`, `is_ip`, `strip_ansi` —
use these so your wrapper handles `http://`-less input, IPs, ports, and trailing
slashes consistently.

## Options & config

Per-module defaults live in `infiltr/config.py`; runtime options are merged in
and reach your wrapper as `self.options`. Advertise them in `OPTIONS_SCHEMA`.

## Registering / reloading

- `python3 runner.py --list-modules` shows the full manifest + install status.
- `POST /modules/reload` hot-reloads the registry (no server restart).
- Invalid wrappers appear under `GET /modules/invalid` with the reason.
