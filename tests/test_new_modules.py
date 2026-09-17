"""katana/naabu/gowitness parsers + native headers/secrets/jslibs collectors."""
import json

from infiltr.modules.katana import KatanaWrapper
from infiltr.modules.naabu import NaabuWrapper
from infiltr.modules.gowitness import GowitnessWrapper
from infiltr.modules.headers import HeadersWrapper
from infiltr.modules.secrets import SecretsWrapper
from infiltr.modules.jslibs import JsLibsWrapper


def test_katana_parser():
    out = "\n".join([
        json.dumps({"endpoint": "http://t/login"}),
        json.dumps({"endpoint": "http://t/search?q=1"}),
        json.dumps({"endpoint": "http://t/login"}),  # dup
    ])
    f = KatanaWrapper().parse_output(out, "", 0)
    assert len(f) == 2
    assert any(x.value == "param" for x in f)


def test_naabu_parser():
    out = "\n".join([json.dumps({"host": "t", "ip": "1.2.3.4", "port": 80}),
                     json.dumps({"host": "t", "ip": "1.2.3.4", "port": 3306})])
    f = NaabuWrapper().parse_output(out, "", 0)
    names = {x.name for x in f}
    assert names == {"80/tcp", "3306/tcp"}
    assert next(x for x in f if x.name == "3306/tcp").severity == "medium"  # db port


def test_gowitness_build_and_empty_parse():
    w = GowitnessWrapper()
    cmd = w.build_command("http://t")
    assert cmd[0] == "gowitness" and "single" in cmd
    assert w.parse_output("", "", 0) == []


# ---- native modules with a stubbed HTTP client ------------------------
def test_headers_missing_and_cors(monkeypatch):
    def fake_fetch(url, method="GET", timeout=15, headers=None, max_bytes=0):
        if headers and headers.get("Origin"):   # CORS probe
            return {"status": 200, "url": url,
                    "headers": {"access-control-allow-origin": "https://evil.example.com",
                                "access-control-allow-credentials": "true"}, "body": ""}
        return {"status": 200, "url": url, "headers": {"server": "nginx/1.18"}, "body": ""}
    monkeypatch.setattr("infiltr.modules.headers.fetch", fake_fetch)
    f = HeadersWrapper().collect("http://t")
    types = {x.type for x in f}
    assert "missing_header" in types
    cors = [x for x in f if x.type == "cors"]
    assert cors and cors[0].severity == "high"   # reflected origin + credentials
    assert any(x.name == "server" for x in f)    # banner disclosure


def test_secrets_exposed_file_and_js(monkeypatch):
    def fake_fetch(url, method="GET", timeout=15, headers=None, max_bytes=0):
        if url.endswith("/.env"):
            return {"status": 200, "url": url, "headers": {}, "body": "DB_PASSWORD=hunter2\nAWS_KEY=x"}
        if url.rstrip("/").endswith("/t") or url.endswith("/"):
            return {"status": 200, "url": url, "headers": {},
                    "body": '<script src="/app.js"></script>'}
        if url.endswith("/app.js"):
            return {"status": 200, "url": url, "headers": {},
                    "body": 'const k="AKIAIOSFODNN7EXAMPLE"; var t="ghp_' + "a" * 36 + '";'}
        return {"status": 404, "url": url, "headers": {}, "body": ""}
    monkeypatch.setattr("infiltr.modules.secrets.fetch", fake_fetch)
    f = SecretsWrapper().collect("http://t")
    assert any(x.type == "exposure" and x.name == "/.env" for x in f)
    secret_names = {x.name for x in f if x.type == "secret"}
    assert "aws-access-key" in secret_names and "github-token" in secret_names


def test_jslibs_detects_outdated(monkeypatch):
    def fake_fetch(url, method="GET", timeout=15, headers=None, max_bytes=0):
        return {"status": 200, "url": url, "headers": {},
                "body": '<script src="/js/jquery-3.4.1.min.js"></script>'}
    monkeypatch.setattr("infiltr.modules.jslibs.fetch", fake_fetch)
    f = JsLibsWrapper().collect("http://t")
    jq = next(x for x in f if x.name == "jquery")
    assert jq.value == "3.4.1"
    assert jq.metadata["outdated"] and jq.severity == "medium"


# ---- takeover / openredirect / secrets extension ----------------------
def test_takeover_body_and_cname(monkeypatch):
    from infiltr.modules.takeover import TakeoverWrapper
    def fake_fetch(url, method="GET", timeout=15, headers=None, max_bytes=0):
        return {"status": 404, "url": url, "headers": {},
                "body": "404 There isn't a GitHub Pages site here."}
    monkeypatch.setattr("infiltr.modules.takeover.fetch", fake_fetch)
    # CNAME confirms the service -> high confidence
    monkeypatch.setattr("socket.gethostbyname_ex",
                        lambda h: ("victim.github.io", ["victim.github.io"], ["185.199.108.153"]))
    f = TakeoverWrapper().collect("http://sub.victim.com")
    hit = next(x for x in f if x.type == "takeover")
    assert hit.metadata["service"] == "github-pages"
    assert hit.metadata["cname_confirmed"] is True
    assert hit.metadata["confidence"] == 0.9


def test_takeover_body_only_lower_confidence(monkeypatch):
    from infiltr.modules.takeover import TakeoverWrapper
    monkeypatch.setattr("infiltr.modules.takeover.fetch",
                        lambda url, **k: {"status": 404, "url": url, "headers": {},
                                          "body": "NoSuchBucket"})
    monkeypatch.setattr("socket.gethostbyname_ex", lambda h: ("1.2.3.4", [], ["1.2.3.4"]))
    f = TakeoverWrapper().collect("http://sub.victim.com")
    hit = next(x for x in f if x.type == "takeover")
    assert hit.metadata["service"] == "aws-s3" and hit.metadata["confidence"] == 0.72


def test_takeover_clean_target_no_finding(monkeypatch):
    from infiltr.modules.takeover import TakeoverWrapper
    monkeypatch.setattr("infiltr.modules.takeover.fetch",
                        lambda url, **k: {"status": 200, "url": url, "headers": {}, "body": "<html>Welcome</html>"})
    monkeypatch.setattr("socket.gethostbyname_ex", lambda h: ("1.2.3.4", [], ["1.2.3.4"]))
    f = TakeoverWrapper().collect("http://ok.victim.com")
    assert not any(x.type == "takeover" for x in f)


def test_openredirect_detects_location(monkeypatch):
    from infiltr.modules.openredirect import OpenRedirectWrapper
    def fake_fetch(url, method="GET", timeout=15, headers=None, max_bytes=0, follow_redirects=True):
        if "next=" in url:
            return {"status": 302, "url": url,
                    "headers": {"location": "https://example.com/infiltr"}, "body": ""}
        return {"status": 200, "url": url, "headers": {}, "body": ""}
    monkeypatch.setattr("infiltr.modules.openredirect.fetch", fake_fetch)
    f = OpenRedirectWrapper().collect("http://t/redirect")
    hits = [x for x in f if x.type == "open_redirect"]
    assert any(x.metadata["param"] == "next" for x in hits)
    assert hits[0].metadata["confidence"] == 0.8


def test_openredirect_no_false_positive(monkeypatch):
    from infiltr.modules.openredirect import OpenRedirectWrapper
    monkeypatch.setattr("infiltr.modules.openredirect.fetch",
                        lambda url, **k: {"status": 200, "url": url, "headers": {}, "body": ""})
    f = OpenRedirectWrapper().collect("http://t/page")
    assert not any(x.type == "open_redirect" for x in f)


def test_secrets_svn_and_bak(monkeypatch):
    def fake_fetch(url, method="GET", timeout=15, headers=None, max_bytes=0):
        if url.endswith("/.svn/entries"):
            return {"status": 200, "url": url, "headers": {}, "body": "12\n\ndir\n"}
        if url.endswith("/config.php.bak"):
            return {"status": 200, "url": url, "headers": {}, "body": "<?php $db_pass='x';"}
        return {"status": 404, "url": url, "headers": {}, "body": ""}
    monkeypatch.setattr("infiltr.modules.secrets.fetch", fake_fetch)
    names = {x.name for x in SecretsWrapper().collect("http://t") if x.type == "exposure"}
    assert "/.svn/entries" in names and "/config.php.bak" in names
