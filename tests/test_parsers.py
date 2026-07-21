"""Feed realistic tool output to each wrapper's parse_output and assert extraction.

This validates the parsing layer without needing the tools installed — the same
regexes/XML paths that run against real DVWA output.
"""
from infiltr.modules.nmap import NmapWrapper
from infiltr.modules.theharvester import TheHarvesterWrapper
from infiltr.modules.whatweb import WhatWebWrapper
from infiltr.modules.feroxbuster import FeroxbusterWrapper
from infiltr.modules.ffuf import FfufWrapper
from infiltr.modules.gobuster import GobusterWrapper
from infiltr.modules.nikto import NiktoWrapper
from infiltr.modules.sqlmap import SqlmapWrapper
from infiltr.modules.wfuzz import WfuzzWrapper
from infiltr.modules.xsstrike import XSStrikeWrapper
from infiltr.modules.hydra import HydraWrapper


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.7"/>
        <script id="http-sql-injection" output="VULNERABLE: possible sqli CVE-2014-0160"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="5.5.44"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_parser():
    f = NmapWrapper().parse_output(NMAP_XML, "", 0)
    ports = [x for x in f if x.type == "open_port"]
    assert {p.name for p in ports} == {"22/tcp", "80/tcp", "3306/tcp"}
    mysql = next(p for p in ports if p.name == "3306/tcp")
    assert mysql.severity == "medium"
    assert any(x.type == "vuln_hint" for x in f)


def test_theharvester_parser():
    out = """[*] Emails found:
admin@target.local
webmaster@target.local

[*] Hosts found:
dev.target.local:10.0.0.5
www.target.local
"""
    f = TheHarvesterWrapper().parse_output(out, "", 0)
    emails = {x.value for x in f if x.type == "email"}
    hosts = {x.value for x in f if x.type == "subdomain"}
    assert "admin@target.local" in emails
    assert "dev.target.local" in hosts


def test_whatweb_parser():
    out = "http://localhost:8080 [200 OK] Apache[2.4.7], PHP[5.5.9], Title[DVWA], Country[RESERVED]"
    f = WhatWebWrapper().parse_output(out, "", 0)
    names = {x.name.lower(): x.value for x in f}
    assert "apache" in names and names["apache"] == "2.4.7"
    assert "php" in names


def test_feroxbuster_parser():
    out = """200      GET       10l       20w   1024c http://localhost:8080/login.php
403      GET        9l       12w    290c http://localhost:8080/config
301      GET        0l        0w      0c http://localhost:8080/admin"""
    f = FeroxbusterWrapper().parse_output(out, "", 0)
    assert len(f) == 3
    forbidden = next(x for x in f if "config" in x.name)
    assert forbidden.severity == "medium"


def test_gobuster_parser():
    out = """/admin                (Status: 301) [Size: 234]
/login.php            (Status: 200) [Size: 1400]
/backup               (Status: 403) [Size: 12]"""
    f = GobusterWrapper().parse_output(out, "", 0)
    assert {x.name for x in f} == {"/admin", "/login.php", "/backup"}


def test_nikto_parser():
    out = """- Nikto v2.5.0
+ Server: Apache/2.4.7 (Ubuntu)
+ /config/: Directory indexing found.
+ OSVDB-3268: /icons/: Possible SQL injection via id parameter.
+ Cookie PHPSESSID created without the httponly flag."""
    f = NiktoWrapper().parse_output(out, "", 0)
    assert any(x.name == "Server" for x in f)
    sqli = next(x for x in f if "sql" in x.detail.lower())
    assert sqli.severity == "high"


def test_sqlmap_parser():
    out = """sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind
    Type: error-based
back-end DBMS: MySQL >= 5.0
available databases [2]:
[*] dvwa
[*] information_schema
"""
    f = SqlmapWrapper().parse_output(out, "", 0)
    inj = [x for x in f if x.type == "sqli"]
    assert inj and inj[0].value == "id" and inj[0].severity == "critical"
    assert any(x.type == "database" and x.value == "dvwa" for x in f)


def test_wfuzz_parser():
    out = """000000001:   C=200      7 L       12 W       145 Ch      "admin"
000000002:   C=403      9 L       20 W       288 Ch      "config"
000000003:   C=200      3 L        5 W        40 Ch      "phpinfo.php\""""
    f = WfuzzWrapper().parse_output(out, "", 0)
    names = {x.name for x in f}
    assert "admin" in names and "config" in names


def test_xsstrike_parser():
    out = """[~] Checking for DOM vulnerabilities
[+] Reflections found: 1
[!] Payload: <script>alert(1)</script>
[+] Vulnerable webpage: http://localhost:8080/vulnerabilities/xss_r/"""
    f = XSStrikeWrapper().parse_output(out, "", 0)
    assert f and all(x.type == "xss" for x in f)
    assert f[0].severity == "high"


def test_hydra_parser():
    out = """[DATA] attacking http-get://127.0.0.1:80/
[80][http-get] host: 127.0.0.1   login: admin   password: password
[80][http-get] host: 127.0.0.1   login: gordonb   password: abc123
1 of 1 target successfully completed"""
    f = HydraWrapper().parse_output(out, "", 0)
    creds = {(x.metadata["login"], x.metadata["password"]) for x in f}
    assert ("admin", "password") in creds
    assert ("gordonb", "abc123") in creds
    assert all(x.severity == "critical" for x in f)


def test_ffuf_parser_reads_json(tmp_path):
    import json
    w = FfufWrapper()
    out = tmp_path / "ffuf.json"
    out.write_text(json.dumps({"results": [
        {"status": 200, "url": "http://localhost:8080/login.php", "length": 1400},
        {"status": 403, "url": "http://localhost:8080/config", "length": 20},
    ]}))
    w._outfile = str(out)
    f = w.parse_output("", "", 0)
    assert len(f) == 2
    assert any(x.severity == "medium" for x in f)
