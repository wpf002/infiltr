"""Native JavaScript library + version fingerprinting.

Extracts client-side library names and versions from the page and its scripts, and
flags a curated set of known end-of-life / vulnerable version ranges. Detection is
deterministic; nuclei's CVE templates provide deeper matching."""
from __future__ import annotations

import re

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import base_url
from ..webutil import fetch

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# library name + version from a filename/url, e.g. jquery-3.4.1.min.js, react@17.0.2
_LIB_RE = re.compile(r"([a-zA-Z][\w.-]*?)[-@/](\d+\.\d+(?:\.\d+)?)", re.I)
# inline version markers, e.g. jQuery v3.4.1
_INLINE = [
    ("jquery", re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)")),
    ("bootstrap", re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)")),
    ("angular", re.compile(r"angular.*?v?(\d+\.\d+\.\d+)", re.I)),
]

# known-outdated thresholds: lib -> (min_safe_major_minor, note)
_OUTDATED = {
    "jquery": ((3, 5), "jQuery < 3.5 has known XSS (CVE-2020-11022/11023)"),
    "bootstrap": ((4, 0), "Bootstrap 3.x is end-of-life"),
    "angular": ((1, 8), "AngularJS 1.x is end-of-life (unsupported)"),
    "lodash": ((4, 17), "lodash < 4.17.21 has prototype-pollution CVEs"),
}
_KNOWN_LIBS = {"jquery", "bootstrap", "angular", "angularjs", "react", "vue", "lodash",
               "moment", "backbone", "ember", "d3", "handlebars", "underscore", "axios"}


class JsLibsWrapper(NativeWrapper):
    MODULE_NAME = "jslibs"
    CATEGORY = "recon"
    DESCRIPTION = "Client-side JS library + version fingerprint (feeds CVE matching)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 30

    def collect(self, target: str) -> list[Finding]:
        root = base_url(target)
        home = fetch(root, timeout=int(self.options.get("timeout", 15)), headers=self.auth_headers())
        libs: dict[str, str] = {}

        for src in _SCRIPT_SRC.findall(home["body"]):
            fname = src.rsplit("/", 1)[-1]
            for name, ver in _LIB_RE.findall(fname):
                n = name.lower().strip("-.")
                if n in _KNOWN_LIBS:
                    libs[n] = ver
        for name, pat in _INLINE:
            m = pat.search(home["body"])
            if m:
                libs.setdefault(name, m.group(1))

        findings: list[Finding] = []
        for name, ver in sorted(libs.items()):
            sev, note = SEV_INFO, ""
            thresh = _OUTDATED.get(name.replace("angularjs", "angular"))
            if thresh and _older_than(ver, thresh[0]):
                sev, note = SEV_MEDIUM, thresh[1]
            findings.append(Finding(
                type="jslib", name=name, value=ver,
                detail=note or "client-side library detected", severity=sev,
                metadata={"library": name, "version": ver, "outdated": bool(note)}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        outdated = sum(1 for f in findings if (f.metadata or {}).get("outdated"))
        return f"{len(findings)} JS librar(y/ies), {outdated} outdated."


def _older_than(version: str, min_mm: tuple[int, int]) -> bool:
    try:
        parts = [int(x) for x in version.split(".")[:2]]
        while len(parts) < 2:
            parts.append(0)
        return (parts[0], parts[1]) < min_mm
    except ValueError:
        return False
