"""Parser validation for the extended toolchain (nuclei, httpx, dalfox, msf, …)."""
import json

from infiltr.modules.nuclei import NucleiWrapper
from infiltr.modules.httpx import HttpxWrapper
from infiltr.modules.subfinder import SubfinderWrapper
from infiltr.modules.dnsx import DnsxWrapper
from infiltr.modules.dalfox import DalfoxWrapper
from infiltr.modules.sslscan import SslscanWrapper
from infiltr.modules.wafw00f import Wafw00fWrapper
from infiltr.modules.wpscan import WpscanWrapper
from infiltr.modules.masscan import MasscanWrapper
from infiltr.modules.metasploit import MetasploitWrapper


def test_nuclei_parser():
    out = "\n".join([
        json.dumps({"template-id": "CVE-2021-1234", "info": {"name": "Example RCE", "severity": "critical", "tags": ["cve", "rce"]}, "matched-at": "http://t/x", "type": "http"}),
        json.dumps({"template-id": "tech-detect", "info": {"name": "Apache", "severity": "info"}, "matched-at": "http://t", "type": "http"}),
    ])
    f = NucleiWrapper().parse_output(out, "", 0)
    crit = [x for x in f if x.severity == "critical"]
    assert crit and crit[0].name == "Example RCE"
    assert any(x.metadata["template_id"] == "tech-detect" for x in f)


def test_httpx_parser():
    out = json.dumps({"url": "http://t", "status_code": 403, "title": "Forbidden",
                      "webserver": "nginx", "tech": ["PHP", "jQuery"], "a": ["1.2.3.4"]})
    f = HttpxWrapper().parse_output(out, "", 0)
    assert any(x.type == "http" and x.value == "403" and x.severity == "medium" for x in f)
    assert any(x.type == "technology" and x.name == "PHP" for x in f)
    assert any(x.type == "ip" and x.value == "1.2.3.4" for x in f)


def test_httpx_stdin():
    # httpx wants host:port (not a scheme'd URL); default port derived from scheme
    assert HttpxWrapper().stdin_for("localhost:8080").strip() == "localhost:8080"
    assert HttpxWrapper().stdin_for("http://dvwa").strip() == "dvwa:80"
    assert HttpxWrapper().stdin_for("https://x.com").strip() == "x.com:443"


def test_subfinder_parser():
    out = "www.target.local\napi.target.local\n\nmail.target.local\n"
    f = SubfinderWrapper().parse_output(out, "", 0)
    assert {x.value for x in f} == {"www.target.local", "api.target.local", "mail.target.local"}


def test_dnsx_parser():
    out = json.dumps({"host": "target.local", "a": ["10.0.0.5"], "cname": ["cdn.example.net"]})
    f = DnsxWrapper().parse_output(out, "", 0)
    assert any(x.type == "dns_a" and x.value == "10.0.0.5" for x in f)
    assert any(x.type == "dns_cname" and x.value == "cdn.example.net" for x in f)


def test_dalfox_parser_array():
    out = json.dumps([{"type": "V", "inject_type": "inHTML-URL", "poc": "<script>alert(1)</script>",
                       "param": "q", "method": "GET", "severity": "High"}])
    f = DalfoxWrapper().parse_output(out, "", 0)
    assert len(f) == 1 and f[0].type == "xss" and f[0].severity == "high"


def test_sslscan_parser():
    out = """  SSLv3     enabled
  TLSv1.0   enabled
  TLSv1.2   enabled
  Accepted  TLSv1.2  56 bits  DES-CBC-SHA
Not valid after:  Jan 1 2020 GMT"""
    f = SslscanWrapper().parse_output(out, "", 0)
    protos = {x.name: x.severity for x in f if x.type == "tls_protocol"}
    assert protos.get("SSLv3") == "high"
    assert protos.get("TLSv1.0") == "medium"
    assert any(x.type == "tls_cipher" for x in f)


def test_wafw00f_parser():
    out = "[*] The site http://t is behind Cloudflare (Cloudflare Inc.) WAF."
    f = Wafw00fWrapper().parse_output(out, "", 0)
    assert f and "Cloudflare" in f[0].value


def test_wafw00f_none():
    f = Wafw00fWrapper().parse_output("[-] No WAF detected by the generic detection", "", 0)
    assert f and f[0].value == "none detected"


def test_wpscan_parser():
    out = json.dumps({
        "version": {"number": "5.2", "vulnerabilities": [{"title": "Core XSS"}]},
        "plugins": {"contact-form-7": {"version": {"number": "5.0"}, "vulnerabilities": [{"title": "CF7 RCE"}]}},
        "users": {"admin": {}, "editor": {}},
    })
    f = WpscanWrapper().parse_output(out, "", 0)
    assert any(x.type == "wp_version" and x.value == "5.2" for x in f)
    assert any(x.type == "vuln" and "RCE" in x.name for x in f)
    assert {x.value for x in f if x.type == "wp_user"} == {"admin", "editor"}


def test_masscan_parser():
    out = "#masscan\nopen tcp 80 45.33.32.156 1493\nopen tcp 443 45.33.32.156 1493"
    f = MasscanWrapper().parse_output(out, "", 0)
    assert {x.name for x in f} == {"80/tcp", "443/tcp"}


def test_metasploit_session_and_login():
    out = """[*] Started reverse handler
[+] 10.0.0.5:80 - Login Successful: 'redteam:letmein123'
[*] Meterpreter session 1 opened (1.2.3.4 -> 10.0.0.5)"""
    f = MetasploitWrapper().parse_output(out, "", 0)
    assert any(x.type == "session" and x.severity == "critical" for x in f)
    creds = [x for x in f if x.type == "credential"]
    assert creds and creds[0].metadata["login"] == "redteam"


def test_metasploit_build_command():
    w = MetasploitWrapper(options={"module": "auxiliary/scanner/http/http_version"})
    cmd = w.build_command("http://victim")
    assert cmd[0] == "msfconsole" and "-x" in cmd
    resource = cmd[-1]
    assert "use auxiliary/scanner/http/http_version" in resource
    assert "set RHOSTS victim" in resource and "run" in resource
