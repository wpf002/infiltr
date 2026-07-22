"""Human-readable explanations for modules and finding types.

Kept separate from the wrappers so the same plain-English text powers the web
console drawer, reports, and the API — without bloating stored scan data.
"""
from __future__ import annotations

# What each module does + how to read its results.
MODULE_EXPLANATIONS: dict[str, str] = {
    "nmap": "Scans network ports and identifies the service and version behind each open one. Open ports are entry points; outdated versions often map to known CVEs.",
    "masscan": "Very fast port sweep across large ranges. Confirms which ports are reachable; follow up with nmap for service/version detail.",
    "theharvester": "Passive OSINT — collects emails, hostnames, IPs and org data from public sources. Shows what an attacker can learn before touching the target.",
    "subfinder": "Enumerates subdomains from passive sources. Each subdomain is an extra host in scope that may run its own, sometimes weaker, services.",
    "dnsx": "Resolves DNS records (A/AAAA/CNAME). Maps hostnames to the IPs and providers actually serving them.",
    "httpx": "Probes web hosts and reports status, title, server, detected technologies and IP. A quick fingerprint of what's running.",
    "whatweb": "Fingerprints the web stack (frameworks, CMS, libraries, versions). Useful for matching components against known vulnerabilities.",
    "wafw00f": "Detects whether a Web Application Firewall sits in front of the site, and which one — affects how other tests should be tuned.",
    "nuclei": "Runs thousands of community templates for known CVEs, exposures and misconfigurations. High-signal: each hit maps to a specific documented issue.",
    "nikto": "Classic web server scanner — checks for dangerous files, outdated software, and common misconfigurations. Verbose; expect some low-signal notes.",
    "feroxbuster": "Brute-forces directories and files recursively. Reveals hidden paths (admin panels, backups, configs) not linked from the site.",
    "ffuf": "Fast web fuzzer for content and parameter discovery. Similar goal to feroxbuster/gobuster with different tuning.",
    "gobuster": "Directory and file brute-forcing to uncover unlinked paths on the web server.",
    "wfuzz": "Web fuzzer for content and parameters; surfaces responses that differ from the norm.",
    "sqlmap": "Automated SQL injection testing. A hit means database queries can be manipulated — potentially full read/write of the database.",
    "xsstrike": "Detects reflected/DOM cross-site scripting and generates working payloads.",
    "dalfox": "Modern XSS scanner. Analyses parameters and confirms cross-site scripting with a proof-of-concept payload.",
    "sslscan": "Enumerates the TLS/SSL protocols, ciphers and certificate of an HTTPS service. Flags weak or deprecated crypto.",
    "testssl": "Deep TLS/SSL audit — protocols, ciphers, and known TLS vulnerabilities (Heartbleed, ROBOT, etc.) with severity.",
    "wpscan": "WordPress-specific scanner — enumerates version, plugins, users and known vulnerabilities.",
    "hydra": "Online credential brute-force / password spraying against a login service. A hit is a working username/password pair.",
    "metasploit": "Runs a Metasploit module (auxiliary scanner by default, exploits when pointed there) against the target for authorized testing.",
}

# What each finding TYPE means and why it matters.
FINDING_EXPLANATIONS: dict[str, str] = {
    "open_port": "A network port accepting connections. Each open port widens the attack surface — check the service and version for known vulnerabilities.",
    "os": "The operating system nmap inferred from the target's network behaviour.",
    "vuln_hint": "An nmap script flagged a possible vulnerability on this port. Verify before relying on it.",
    "email": "An email address tied to the target — useful for phishing pretexts or as a username guess.",
    "subdomain": "An additional hostname belonging to the target. Bring it into scope and scan it too; it may be less hardened than the main site.",
    "ip": "An IP address associated with the target.",
    "asn": "The Autonomous System (network owner) hosting the target — indicates the provider/network block.",
    "linkedin": "A LinkedIn profile linked to the organisation — useful for social-engineering context.",
    "technology": "A software component and version running on the target. Match the version against public CVE databases.",
    "title": "The page title returned by the server — a quick hint at what the app is.",
    "http": "The HTTP status the server returned. 401/403 mean a resource exists but is protected; worth investigating.",
    "header": "An HTTP response header of interest (e.g. the server banner), which can reveal software and versions.",
    "path": "A reachable URL path found by brute force. Admin, config, or backup paths can expose sensitive functionality or data.",
    "finding": "A web server issue reported by nikto — could be an exposed file, an outdated component, or a misconfiguration.",
    "sqli": "SQL injection: user input reaches a database query unsafely, potentially exposing or altering the entire database. Treat as critical.",
    "dbms": "The database engine identified behind the application.",
    "database": "A database name recovered from the target — evidence the injection can read schema data.",
    "table": "A database table recovered from the target — evidence data can be enumerated.",
    "xss": "Cross-site scripting: the app reflects attacker input into a page without sanitising it, letting an attacker run JavaScript in victims' browsers (session theft, defacement).",
    "credential": "A valid username/password pair — anyone can authenticate with it. Rotate immediately.",
    "session": "A remote session or shell was obtained on the target — this indicates full compromise.",
    "msf": "A result reported by a Metasploit module.",
    "vuln": "A known vulnerability or misconfiguration matched by a signature/template. Usually maps to a specific CVE or advisory.",
    "dns_a": "An IPv4 (A) DNS record for the host.",
    "dns_aaaa": "An IPv6 (AAAA) DNS record for the host.",
    "dns_cname": "A CNAME alias — the host points at another name (often a CDN or SaaS provider).",
    "waf": "Whether a Web Application Firewall is present, and which product. Affects how aggressively other tools should probe.",
    "tls_protocol": "A TLS/SSL protocol version the server accepts. Old versions (SSLv3, TLS 1.0/1.1) are deprecated and weaken the connection.",
    "tls_cipher": "A cipher suite the server accepts. Short keys or legacy ciphers can be broken.",
    "tls": "A TLS/SSL configuration issue or known vulnerability reported by testssl.",
    "certificate": "Details of the server's TLS certificate (e.g. expiry).",
    "wp_version": "The detected WordPress core version — check it against known WordPress CVEs.",
    "wp_plugin": "A WordPress plugin (and version) — plugins are the most common source of WordPress vulnerabilities.",
    "wp_user": "A WordPress username enumerated from the site — halves the work for a login brute-force.",
}

_DEFAULT_FINDING = "A result reported by this module. See the raw output for detail."
_DEFAULT_MODULE = "A security scanning module."


def module_explanation(name: str) -> str:
    return MODULE_EXPLANATIONS.get(name, _DEFAULT_MODULE)


def finding_explanation(ftype: str) -> str:
    return FINDING_EXPLANATIONS.get(ftype, _DEFAULT_FINDING)


def all_explanations() -> dict[str, dict[str, str]]:
    return {"modules": MODULE_EXPLANATIONS, "findings": FINDING_EXPLANATIONS}
