"""Every wrapper's parse_output must survive garbage/empty/truncated input."""
import pytest

from infiltr import engine

GARBAGE = [
    "",
    "   \n\n  ",
    "not json at all { [ ] ",
    '{"incomplete": ',
    "[{},{},{}]",
    "\x00\x01\x02\xff binary noise",
    "PORT STATE SERVICE\n" * 1000,          # large-ish
    "<html><body>error page</body></html>",
    "\x1b[31mANSI\x1b[0m colored garbage",
]

MODULES = sorted(engine.discover())


@pytest.mark.parametrize("name", MODULES)
def test_parse_output_never_raises(name):
    cls = engine.discover()[name]
    wrapper = cls(options={})
    for blob in GARBAGE:
        out = wrapper.parse_output(blob, blob, 1)
        assert isinstance(out, list)
        for f in out:
            assert hasattr(f, "severity") and hasattr(f, "type")


@pytest.mark.parametrize("name", MODULES)
def test_summarize_never_raises(name):
    cls = engine.discover()[name]
    wrapper = cls(options={})
    findings = wrapper.parse_output("", "", 0)
    assert isinstance(wrapper.summarize(findings), str)
