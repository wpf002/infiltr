"""Per-module integration tests against the lab target.

Each test is skipped when the tool isn't installed, so the suite is green on any
machine. On a box with the tools + DVWA up, they assert real execution succeeds.

Run the full live suite:
    docker compose up -d
    INFILTR_TEST_TARGET=http://localhost:8080 pytest tests/test_integration.py
"""
import pytest

from infiltr.engine import discover
from infiltr.base import ERROR
from tests.conftest import TARGET

REGISTRY = discover()
EXPECTED = {
    "nmap", "theharvester", "whatweb", "feroxbuster", "ffuf", "gobuster",
    "nikto", "sqlmap", "wfuzz", "xsstrike", "hydra",
}


def test_all_modules_registered():
    assert EXPECTED.issubset(set(REGISTRY))


def test_engine_discovers_eleven():
    assert len(REGISTRY) >= 11


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_module_runs(name):
    cls = REGISTRY[name]
    if not cls.is_installed():
        pytest.skip(f"{cls.TOOL_BIN} not installed")
    from infiltr import config
    wrapper = cls(options=config.for_module(name, {"timeout": 120}))
    result = wrapper.run(TARGET)
    assert result.status != ERROR, f"{name} errored: {result.error}"
    # findings may be empty, but the pipeline must complete cleanly
    assert result.command
    assert result.finished_at


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_build_command_is_list(name):
    """Command construction must not raise for any target shape."""
    cls = REGISTRY[name]
    from infiltr import config
    wrapper = cls(options=config.for_module(name))
    for target in ("http://localhost:8080", "localhost:8080", "127.0.0.1"):
        cmd = wrapper.build_command(target)
        assert isinstance(cmd, list) and all(isinstance(x, str) for x in cmd)
