"""Native subdomain-takeover detection for a single target.

Checks ONLY the given host: resolves its CNAME/canonical name and matches the
served page against known "unclaimed service" fingerprints. Does not enumerate
subdomains (that would expand scope). A flag requires the distinctive body
signature of a dangling service; the CNAME hint raises confidence when present.
"""
from __future__ import annotations

import socket

from ..base import NativeWrapper, Finding, SEV_INFO, SEV_HIGH
from ..utils import base_url, hostname
from ..webutil import fetch

# service -> (body signature, cname substring hint). Curated, distinctive strings
# (from the public can-i-take-over-xyz matrix) to keep false positives low.
_FINGERPRINTS = {
    "github-pages": ("There isn't a GitHub Pages site here.", "github.io"),
    "heroku": ("No such app", "herokudns.com"),
    "aws-s3": ("NoSuchBucket", "amazonaws.com"),
    "fastly": ("Fastly error: unknown domain", "fastly.net"),
    "shopify": ("Sorry, this shop is currently unavailable", "myshopify.com"),
    "zendesk": ("Help Center Closed", "zendesk.com"),
    "cargo": ("If you're moving your domain away from Cargo", "cargocollective.com"),
    "wpengine": ("The site you were looking for couldn't be found", "wpengine.com"),
    "pantheon": ("The gods are wise, but do not know of the site", "pantheonsite.io"),
    "tumblr": ("Whatever you were looking for doesn't currently exist", "domains.tumblr.com"),
    "bitbucket": ("Repository not found", "bitbucket.io"),
    "readthedocs": ("unknown to Read the Docs", "readthedocs.io"),
}


class TakeoverWrapper(NativeWrapper):
    MODULE_NAME = "takeover"
    CATEGORY = "recon"
    DESCRIPTION = "Subdomain-takeover check for the target host (dangling CNAME + service fingerprint)"
    VERSION = "1.0"
    DEFAULT_TIMEOUT = 30

    def collect(self, target: str) -> list[Finding]:
        host = hostname(target)
        aliases = self._cname_chain(host)
        r = fetch(base_url(target), timeout=int(self.options.get("timeout", 15)),
                  headers=self.auth_headers())
        body = r.get("body", "") or ""

        findings: list[Finding] = []
        for service, (sig, cname_hint) in _FINGERPRINTS.items():
            if sig.lower() not in body.lower():
                continue
            cname_match = any(cname_hint in a for a in aliases)
            # body signature alone = candidate; + matching CNAME = strong.
            confidence = 0.9 if cname_match else 0.72
            findings.append(Finding(
                type="takeover", name=f"{service} takeover", value=host,
                detail=(f"page serves {service}'s unclaimed-resource response"
                        + (f"; CNAME points to {cname_hint}" if cname_match else
                           " (no confirming CNAME — verify the DNS target is claimable)")),
                severity=SEV_HIGH,
                metadata={"service": service, "url": r.get("url"), "cname_chain": aliases,
                          "cname_confirmed": cname_match, "confidence": confidence}))
        if not findings and aliases:
            # nothing exploitable, but record the CNAME chain as info for the operator
            findings.append(Finding(
                type="note", name="cname", value=" -> ".join(aliases)[:200],
                detail="canonical/CNAME chain (no takeover signature matched)", severity=SEV_INFO,
                metadata={"cname_chain": aliases}))
        return findings

    def summarize(self, findings: list[Finding]) -> str:
        n = sum(1 for f in findings if f.type == "takeover")
        return f"{n} subdomain-takeover candidate(s)." if n else "No takeover signature."

    @staticmethod
    def _cname_chain(host: str) -> list[str]:
        try:
            canonical, aliases, _ = socket.gethostbyname_ex(host)
            chain = [a for a in ([canonical] + list(aliases)) if a and a.lower() != host.lower()]
            # de-dup preserving order
            seen: set[str] = set()
            return [c for c in chain if not (c.lower() in seen or seen.add(c.lower()))]
        except (socket.gaierror, socket.herror, OSError):
            return []
