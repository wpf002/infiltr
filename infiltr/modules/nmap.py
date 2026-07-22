"""Nmap wrapper — service/version discovery via XML output."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import hostname


class NmapWrapper(BaseWrapper):
    MODULE_NAME = "nmap"
    CATEGORY = "recon"
    TOOL_BIN = "nmap"
    DESCRIPTION = "Port scan + service/version detection"
    VERSION = "1.1"
    OPTIONS_SCHEMA = {
        "ports": {"type": "string", "default": "top1000", "help": "'top1000' | range | csv"},
        "scripts": {"type": "string", "default": "default", "help": "'default' | 'vuln' | script name"},
        "flags": {"type": "list", "default": ["-sT", "-sV", "-T4", "-Pn"], "help": "raw nmap flags (-sT for unprivileged connect scan)"},
    }
    DEFAULT_TIMEOUT = 600

    def build_command(self, target: str) -> list[str]:
        host = hostname(target)
        cmd = [self.TOOL_BIN, *self.options.get("flags", ["-sT", "-sV", "-T4", "-Pn"])]

        ports = self.options.get("ports", "top1000")
        if ports == "top1000":
            cmd += ["--top-ports", "1000"]
        elif ports:
            cmd += ["-p", str(ports)]

        scripts = self.options.get("scripts")
        if scripts == "default":
            cmd.append("-sC")
        elif scripts:
            cmd += ["--script", str(scripts)]

        cmd += ["-oX", "-", host]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        findings: list[Finding] = []
        stdout = stdout.strip()
        if not stdout.startswith("<?xml"):
            return findings
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return findings

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else ""

            os_el = host.find("os/osmatch")
            if os_el is not None:
                findings.append(
                    Finding(
                        type="os",
                        name="os_guess",
                        value=os_el.get("name", ""),
                        detail=f"accuracy {os_el.get('accuracy', '?')}%",
                        severity=SEV_INFO,
                    )
                )

            for port in host.findall("ports/port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = port.get("portid", "")
                proto = port.get("protocol", "")
                svc = port.find("service")
                svc_name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                banner = " ".join(x for x in [product, version] if x)

                sev = SEV_INFO
                if svc_name in {
                    "telnet", "ftp", "rlogin", "vnc",
                    "mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "oracle-tns",
                }:
                    sev = SEV_MEDIUM
                elif svc_name in {"http", "https", "ssh", "smb", "microsoft-ds", "rdp"}:
                    sev = SEV_LOW

                findings.append(
                    Finding(
                        type="open_port",
                        name=f"{portid}/{proto}",
                        value=svc_name,
                        detail=banner,
                        severity=sev,
                        metadata={
                            "port": portid,
                            "protocol": proto,
                            "product": product,
                            "version": version,
                            "address": addr,
                        },
                    )
                )

                # CVE hints from vuln scripts
                for script in port.findall("script"):
                    out = script.get("output", "")
                    if "CVE-" in out or "VULNERABLE" in out.upper():
                        findings.append(
                            Finding(
                                type="vuln_hint",
                                name=script.get("id", "script"),
                                value=f"port {portid}",
                                detail=out.strip()[:400],
                                severity=SEV_MEDIUM,
                            )
                        )
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        ports = [f for f in findings if f.type == "open_port"]
        return f"{len(ports)} open port(s)." if ports else "No open ports found."
