"""sslscan wrapper — TLS/SSL protocol + cipher + certificate audit."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH
from ..utils import host_port, strip_ansi

_PROTO_RE = re.compile(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)", re.I)
_WEAK_PROTOS = {"sslv2", "sslv3", "tlsv1.0", "tlsv1.1"}


class SslscanWrapper(BaseWrapper):
    MODULE_NAME = "sslscan"
    CATEGORY = "web"
    TOOL_BIN = "sslscan"
    DESCRIPTION = "TLS/SSL protocol, cipher, and certificate audit"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 180

    def build_command(self, target: str) -> list[str]:
        host, port = host_port(target)
        return [self.TOOL_BIN, "--no-colour", f"{host}:{port or 443}"]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        for proto, state in _PROTO_RE.findall(text):
            if state.lower() == "enabled":
                weak = proto.lower() in _WEAK_PROTOS
                findings.append(
                    Finding(
                        type="tls_protocol",
                        name=proto,
                        value="enabled",
                        detail="deprecated/weak protocol enabled" if weak else "",
                        severity=SEV_HIGH if proto.lower() in {"sslv2", "sslv3"} else (
                            SEV_MEDIUM if weak else SEV_INFO),
                    )
                )
        # weak ciphers
        for m in re.finditer(r"Accepted\s+(\S+)\s+(\d+)\s+bits\s+(\S+)", text):
            bits = int(m.group(2))
            if bits and bits < 128:
                findings.append(
                    Finding(type="tls_cipher", name=m.group(3), value=f"{bits}-bit",
                            detail="weak cipher", severity=SEV_MEDIUM)
                )
        # cert expiry
        exp = re.search(r"Not valid after:\s*(.+)", text)
        if exp:
            findings.append(Finding(type="certificate", name="expires", value=exp.group(1).strip(), severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        weak = sum(1 for f in findings if f.severity in (SEV_MEDIUM, SEV_HIGH))
        return f"{len(findings)} TLS finding(s), {weak} weak."
