"""Signing-key strength gate used at startup when auth is enabled."""
from infiltr.api.app import check_secret_strength


def test_missing_secret_rejected():
    assert check_secret_strength("") is not None


def test_short_secret_rejected():
    assert check_secret_strength("tooshort") is not None
    assert check_secret_strength("a" * 31) is not None


def test_placeholder_secret_rejected():
    for weak in ("changeme", "CHANGEME", "your-secret-key", "password"):
        assert check_secret_strength(weak) is not None, weak


def test_strong_secret_accepted():
    import secrets
    assert check_secret_strength(secrets.token_urlsafe(48)) is None
    assert check_secret_strength("a" * 32) is None
