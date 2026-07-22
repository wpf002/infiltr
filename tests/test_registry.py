"""Plugin/module registry: manifests, validation, hot reload."""
from infiltr.base import BaseWrapper, Finding
from infiltr import engine


def test_all_modules_have_manifests():
    mans = {m["name"]: m for m in engine.manifests()}
    assert len(mans) >= 11
    for name, m in mans.items():
        assert m["version"]
        assert m["category"] in {"recon", "web", "auth", "misc", "exploit"}
        assert "options_schema" in m
        assert "installed" in m


def test_nmap_advertises_options():
    mans = {m["name"]: m for m in engine.manifests()}
    assert "ports" in mans["nmap"]["options_schema"]


def test_no_invalid_real_modules():
    # the 11 shipped wrappers must all validate cleanly
    assert engine.invalid_modules() == {}


def test_validate_catches_broken_wrapper():
    class Broken(BaseWrapper):
        MODULE_NAME = "base"      # not overridden
        CATEGORY = "nonsense"
        TOOL_BIN = ""
        # build_command / parse_output not overridden

    errors = Broken.validate()
    assert any("MODULE_NAME" in e for e in errors)
    assert any("CATEGORY" in e for e in errors)
    assert any("TOOL_BIN" in e for e in errors)
    assert any("build_command" in e for e in errors)
    assert any("parse_output" in e for e in errors)


def test_valid_wrapper_passes():
    class Good(BaseWrapper):
        MODULE_NAME = "good"
        CATEGORY = "web"
        TOOL_BIN = "good"

        def build_command(self, target):
            return [self.TOOL_BIN, target]

        def parse_output(self, stdout, stderr, rc):
            return [Finding(type="x", name="y")]

    assert Good.validate() == []
    assert Good.manifest()["name"] == "good"


def test_hot_reload_rebuilds_registry():
    reg = engine.reload()
    assert len(reg) >= 11
    assert "nmap" in reg
