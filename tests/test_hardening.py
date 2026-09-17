"""Regression tests for the SaaS launch-hardening (SSRF, option/arg injection, RBAC)."""
import pytest

from infiltr import safety
from infiltr.safety import ScopeError
from infiltr.modules.metasploit import MetasploitWrapper
from infiltr.modules.nmap import NmapWrapper
from infiltr.modules.hydra import HydraWrapper


# ---- SSRF / private-IP blocking ---------------------------------------
def test_block_private_targets(monkeypatch):
    monkeypatch.setenv("INFILTR_BLOCK_PRIVATE", "1")
    monkeypatch.delenv("INFILTR_ALLOWLIST", raising=False)
    for internal in ["http://127.0.0.1", "http://10.0.0.5", "http://192.168.1.1",
                     "http://169.254.169.254", "http://[::1]"]:
        assert not safety.is_in_scope(internal), internal


def test_public_target_allowed_when_blocking_private(monkeypatch):
    monkeypatch.setenv("INFILTR_BLOCK_PRIVATE", "1")
    monkeypatch.delenv("INFILTR_ALLOWLIST", raising=False)
    assert safety.is_in_scope("http://93.184.216.34")   # public IP literal


def test_block_private_off_allows_lab(monkeypatch):
    monkeypatch.setenv("INFILTR_BLOCK_PRIVATE", "0")
    monkeypatch.delenv("INFILTR_ALLOWLIST", raising=False)
    assert safety.is_in_scope("http://10.0.0.5")


# ---- scan-option sanitization -----------------------------------------
def test_sanitize_rejects_flag_and_metachar_values(monkeypatch):
    monkeypatch.setenv("INFILTR_LOCK_OPTIONS", "0")
    with pytest.raises(ScopeError):
        safety.sanitize_options({"nmap": {"ports": "-oN/tmp/x"}})
    with pytest.raises(ScopeError):
        safety.sanitize_options({"sqlmap": {"level": "1; rm -rf /"}})


def test_locked_mode_drops_dangerous_keys(monkeypatch):
    monkeypatch.setenv("INFILTR_LOCK_OPTIONS", "1")
    out = safety.sanitize_options({
        "nmap": {"ports": "80,443", "flags": ["-oN", "/tmp/x"], "scripts": "../evil"},
        "metasploit": {"module": "exploit/multi/handler", "payload": "cmd/unix/reverse"},
        "hydra": {"userlist": "/etc/passwd"},
    })
    assert out.get("nmap") == {"ports": "80,443"}   # only the safe key survives
    assert "metasploit" not in out                   # no user-tweakable keys
    assert "hydra" not in out


# ---- wrapper-level argument-injection guards --------------------------
def test_metasploit_rejects_exploit_modules(monkeypatch):
    monkeypatch.delenv("INFILTR_MSF_ALLOW_EXPLOIT", raising=False)
    w = MetasploitWrapper(options={"module": "exploit/multi/handler", "payload": "cmd/unix/reverse"})
    with pytest.raises(ValueError):
        w.build_command("http://target")


def test_metasploit_strips_rhosts_and_payload(monkeypatch):
    monkeypatch.delenv("INFILTR_MSF_ALLOW_EXPLOIT", raising=False)
    w = MetasploitWrapper(options={
        "module": "auxiliary/scanner/http/http_version",
        "payload": "cmd/unix/reverse",
        "opts": {"RHOSTS": "10.0.0.1", "AUTH_URI": "/"},
    })
    resource = w.build_command("http://victim")[-1]
    assert "set RHOSTS victim" in resource
    assert "10.0.0.1" not in resource          # user RHOSTS override dropped
    assert "PAYLOAD" not in resource           # no payload on an auxiliary scan
    assert "set AUTH_URI /" in resource        # benign opt kept


def test_nmap_filters_unsafe_flags_and_scripts():
    w = NmapWrapper(options={"flags": ["-sT", "-oN", "/tmp/x", "--datadir"], "scripts": "../../evil.nse"})
    cmd = w.build_command("http://target")
    assert "-oN" not in cmd and "--datadir" not in cmd and "/tmp/x" not in cmd
    assert "--script" not in cmd               # arbitrary script name ignored
    assert "-sT" in cmd


def test_hydra_rejects_bad_service_and_path():
    w = HydraWrapper(options={"service": "http-get", "path": "/ok:extra:inject",
                              "userlist": "u", "passlist": "p"})
    cmd = w.build_command("http://target")
    # injected hydra field separators are stripped -> falls back to '/'
    assert cmd[-1] == "/"
