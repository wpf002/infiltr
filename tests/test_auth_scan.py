"""Authenticated-scan capability + ZAP alert parsing."""
from infiltr.modules.zap import parse_alerts, ZapWrapper
from infiltr.modules.nuclei import NucleiWrapper
from infiltr import engine


def test_zap_parse_alerts():
    alerts = [
        {"alert": "SQL Injection", "risk": "High", "confidence": "Medium", "url": "http://t/p?id=1",
         "param": "id", "cweid": "89", "evidence": "syntax error"},
        {"alert": "X-Frame-Options Header Not Set", "risk": "Medium", "url": "http://t/", "cweid": "16"},
        {"alert": "SQL Injection", "risk": "High", "url": "http://t/p?id=1", "param": "id"},  # dup
    ]
    f = parse_alerts(alerts)
    assert len(f) == 2
    sqli = next(x for x in f if "SQL" in x.name)
    assert sqli.severity == "high" and sqli.metadata["cwe"] == "89"


def test_zap_is_native_and_binary_gated():
    assert ZapWrapper.IS_NATIVE is True
    # unlike other native modules, ZAP needs the zaproxy binary
    import shutil
    assert ZapWrapper.is_installed() == (shutil.which("zaproxy") is not None)


# ---- auth header injection --------------------------------------------
def test_header_args():
    w = NucleiWrapper(options={"auth_headers": {"Cookie": "session=abc", "Authorization": "Bearer t"}})
    args = w.header_args("-H")
    assert args == ["-H", "Cookie: session=abc", "-H", "Authorization: Bearer t"]


def test_no_auth_headers_no_args():
    assert NucleiWrapper(options={}).header_args("-H") == []


def test_engine_injects_auth_headers():
    eng = engine.Engine(modules=["nuclei"], auth_headers={"Cookie": "x=1"})
    w = eng._instantiate("nuclei")
    assert w.auth_headers() == {"Cookie": "x=1"}


def test_build_auth_headers_strips_injection():
    from infiltr.api.app import _build_auth_headers, AuthSpec
    h = _build_auth_headers(AuthSpec(headers={"X-Ok": "v", "-bad": "x", "we:ird": "y"},
                                     cookie="s=1", bearer="tok"))
    assert h["X-Ok"] == "v" and h["Cookie"] == "s=1" and h["Authorization"] == "Bearer tok"
    assert "-bad" not in h and "we:ird" not in h   # flag/colon-injection names dropped
