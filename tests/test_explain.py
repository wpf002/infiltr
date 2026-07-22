"""Human-readable explanations: coverage for every module + common finding types."""
from infiltr import explain, engine


def test_every_module_has_explanation():
    for name in engine.discover():
        text = explain.module_explanation(name)
        assert text and text != explain._DEFAULT_MODULE, f"{name} has no explanation"
        assert len(text) > 30


def test_common_finding_types_explained():
    for ftype in ["open_port", "xss", "sqli", "credential", "vuln", "subdomain",
                  "technology", "path", "tls_protocol", "waf", "session"]:
        text = explain.finding_explanation(ftype)
        assert text and text != explain._DEFAULT_FINDING, f"{ftype} not explained"


def test_unknown_type_gets_default():
    assert explain.finding_explanation("nonexistent-type") == explain._DEFAULT_FINDING


def test_all_explanations_shape():
    data = explain.all_explanations()
    assert "modules" in data and "findings" in data
    assert data["findings"]["xss"].lower().startswith("cross-site")
