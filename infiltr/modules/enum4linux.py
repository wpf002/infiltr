"""enum4linux-ng wrapper — SMB/NetBIOS enumeration for Windows/infra targets.

Enumerates shares, users, groups, OS and domain info over SMB (139/445).
Non-destructive read-only enumeration."""
from __future__ import annotations

import json
import os
import tempfile

from ..base import BaseWrapper, Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM
from ..utils import hostname


class Enum4linuxWrapper(BaseWrapper):
    MODULE_NAME = "enum4linux"
    CATEGORY = "recon"
    TOOL_BIN = "enum4linux-ng"
    DESCRIPTION = "SMB/NetBIOS enumeration: shares, users, groups, OS, domain"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 300

    def build_command(self, target: str) -> list[str]:
        self._out = tempfile.NamedTemporaryFile(prefix="infiltr_e4l_", delete=False).name
        # -A = all simple enumeration (read-only); -oJ writes <path>.json
        return [self.TOOL_BIN, "-A", "-oJ", self._out, hostname(target)]

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        path = getattr(self, "_out", "") + ".json"
        data = None
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    data = json.load(fh)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []

        os_info = data.get("os_info")
        if isinstance(os_info, dict) and any(os_info.values()):
            val = os_info.get("OS") or os_info.get("os") or ""
            findings.append(Finding(type="os", name="OS", value=str(val)[:120],
                                    detail=json.dumps(os_info)[:300], severity=SEV_INFO))

        dom = data.get("smb_domain_info") or data.get("workgroup")
        if dom and not _is_error(dom):
            findings.append(Finding(type="domain", name="SMB domain/workgroup",
                                    value=str(dom if isinstance(dom, str) else dom.get("Workgroup", dom))[:120],
                                    severity=SEV_INFO))

        shares = data.get("shares")
        if isinstance(shares, dict):
            for name, info in shares.items():
                if _is_error(info):
                    continue
                access = ""
                if isinstance(info, dict):
                    access = str(info.get("mapping") or info.get("access") or "")
                sev = SEV_MEDIUM if "ok" in access.lower() or "read" in access.lower() else SEV_LOW
                findings.append(Finding(type="smb_share", name=name, value=access or "share",
                                        detail=f"SMB share {name}", severity=sev,
                                        metadata=info if isinstance(info, dict) else {}))

        users = data.get("users")
        if isinstance(users, dict):
            for rid, info in users.items():
                if _is_error(info):
                    continue
                uname = info.get("username") if isinstance(info, dict) else str(info)
                if uname:
                    findings.append(Finding(type="smb_user", name="user", value=str(uname),
                                            severity=SEV_LOW, metadata={"rid": rid}))

        groups = data.get("groups")
        if isinstance(groups, dict):
            for _, info in groups.items():
                if _is_error(info):
                    continue
                gname = info.get("groupname") if isinstance(info, dict) else str(info)
                if gname:
                    findings.append(Finding(type="smb_group", name="group", value=str(gname), severity=SEV_INFO))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        sh = sum(1 for f in findings if f.type == "smb_share")
        us = sum(1 for f in findings if f.type == "smb_user")
        return f"{sh} share(s), {us} user(s) enumerated." if findings else "No SMB info (host may not expose SMB)."


def _is_error(v) -> bool:
    return isinstance(v, dict) and "error" in v and len(v) == 1
