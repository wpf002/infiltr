"""WhatWeb wrapper — technology fingerprinting."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW
from ..utils import normalize_url, strip_ansi

# Splits "Apache[2.4.7], PHP[5.5.9], Title[Login]" respecting bracket contents.
_PLUGIN_RE = re.compile(r"([A-Za-z0-9 _./-]+?)(?:\[([^\]]*)\])?(?:,|$)")


class WhatWebWrapper(BaseWrapper):
    MODULE_NAME = "whatweb"
    CATEGORY = "recon"
    TOOL_BIN = "whatweb"
    DESCRIPTION = "Web technology fingerprinting"
    DEFAULT_TIMEOUT = 120

    def build_command(self, target: str) -> list[str]:
        url = normalize_url(target)
        aggr = int(self.options.get("aggression", 1))
        if aggr not in (1, 3, 4):   # whatweb only accepts 1, 3, or 4
            aggr = 1
        return [self.TOOL_BIN, "--color=never", "-a", str(aggr), url]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or "://" not in line:
                continue
            # Strip the leading "http://host [200 OK] " chunk.
            head, _, rest = line.partition("]")
            body = rest.strip() if rest else line
            for name, ver in _PLUGIN_RE.findall(body):
                name = name.strip().strip(",").strip()
                if not name or len(name) < 2 or name.startswith("http"):
                    continue
                sev = SEV_LOW if name.lower() in {
                    "php", "apache", "nginx", "iis", "openssl", "jquery", "wordpress"
                } else SEV_INFO
                findings.append(
                    Finding(
                        type="technology",
                        name=name,
                        value=ver.strip(),
                        severity=sev,
                    )
                )
        # de-dup by (name,value)
        uniq: dict[tuple, Finding] = {}
        for f in findings:
            uniq[(f.name.lower(), f.value)] = f
        return list(uniq.values())

    def summarize(self, findings: list[Finding]) -> str:
        return f"{len(findings)} technolog(y/ies) identified."
