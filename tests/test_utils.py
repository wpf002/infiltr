"""Target normalization edge cases: scheme, IP vs host, ports, trailing slashes."""
import pytest

from infiltr import utils


@pytest.mark.parametrize("raw,expected", [
    ("localhost:8080", "http://localhost:8080"),
    ("http://localhost:8080", "http://localhost:8080"),
    ("https://example.com/", "https://example.com"),
    ("example.com/dvwa/", "http://example.com/dvwa/"),
    ("http://1.2.3.4:80/", "http://1.2.3.4:80"),
])
def test_normalize_url(raw, expected):
    assert utils.normalize_url(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("http://localhost:8080/app", "localhost"),
    ("1.2.3.4", "1.2.3.4"),
    ("https://sub.example.com:443/x", "sub.example.com"),
    ("example.com", "example.com"),
])
def test_hostname(raw, expected):
    assert utils.hostname(raw) == expected


@pytest.mark.parametrize("raw,host,port", [
    ("http://localhost:8080", "localhost", 8080),
    ("https://example.com", "example.com", None),
    ("10.0.0.1:22", "10.0.0.1", 22),
])
def test_host_port(raw, host, port):
    assert utils.host_port(raw) == (host, port)


def test_base_url_strips_path():
    assert utils.base_url("http://localhost:8080/dvwa/login.php") == "http://localhost:8080"


def test_is_ip():
    assert utils.is_ip("http://127.0.0.1:8080")
    assert not utils.is_ip("http://example.com")


def test_strip_ansi():
    assert utils.strip_ansi("\x1b[32mgreen\x1b[0m") == "green"
