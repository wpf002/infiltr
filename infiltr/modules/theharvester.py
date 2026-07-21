"""theHarvester wrapper — OSINT emails / hosts / subdomains."""
from __future__ import annotations

import re

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW
from ..utils import hostname, strip_ansi

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HOST_RE = re.compile(r"^([a-z0-9.-]+\.[a-z]{2,})(?::(\d+))?(?:\s*:\s*([\d.]+))?$", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class TheHarvesterWrapper(BaseWrapper):
    MODULE_NAME = "theharvester"
    CATEGORY = "recon"
    TOOL_BIN = "theHarvester"
    DESCRIPTION = "OSINT gathering: emails, subdomains, hosts, IPs"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        domain = hostname(target)
        return [
            self.TOOL_BIN,
            "-d", domain,
            "-b", str(self.options.get("sources", "bing,duckduckgo,crtsh")),
            "-l", str(self.options.get("limit", 200)),
        ]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        text = strip_ansi(stdout)
        findings: list[Finding] = []
        seen: set[str] = set()

        for email in sorted(set(_EMAIL_RE.findall(text))):
            key = f"email:{email}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(type="email", name="email", value=email, severity=SEV_LOW)
            )

        # Hosts section — theHarvester lists "host:ip" lines after "[*] Hosts found"
        in_hosts = False
        for line in text.splitlines():
            s = line.strip()
            low = s.lower()
            if "hosts found" in low or "subdomain" in low:
                in_hosts = True
                continue
            if s.startswith("[") or not s:
                if s.startswith("[*]"):
                    in_hosts = "host" in low or "subdomain" in low
                continue
            if in_hosts:
                m = _HOST_RE.match(s)
                if m:
                    host = m.group(1)
                    ip = m.group(3) or ""
                    key = f"host:{host}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            type="subdomain",
                            name="host",
                            value=host,
                            detail=ip,
                            severity=SEV_INFO,
                            metadata={"ip": ip},
                        )
                    )

        for ip in sorted(set(_IP_RE.findall(text))):
            key = f"ip:{ip}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(type_ip(ip))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        e = sum(1 for f in findings if f.type == "email")
        h = sum(1 for f in findings if f.type == "subdomain")
        return f"{e} email(s), {h} host(s)."


def type_ip(ip: str) -> Finding:
    return Finding(type="ip", name="ip", value=ip, severity=SEV_INFO)
