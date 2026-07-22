"""Flint AI layer — offline heuristics + the annotate-don't-score invariant."""
import copy

from infiltr.ai import Flint


SCAN = {
    "id": 1, "target": "http://localhost:8080", "module_count": 3, "finding_count": 4,
    "top_severity": "critical",
    "results": [
        {"module": "sqlmap", "category": "web", "status": "PASS", "severity": "critical",
         "summary": "1 injectable point.",
         "findings": [{"type": "sqli", "name": "injectable parameter", "value": "id",
                       "detail": "boolean-based blind", "severity": "critical"}]},
        {"module": "nmap", "category": "recon", "status": "PASS", "severity": "medium",
         "summary": "2 open ports.",
         "findings": [{"type": "open_port", "name": "3306/tcp", "value": "mysql", "detail": "", "severity": "medium"},
                      {"type": "open_port", "name": "80/tcp", "value": "http", "detail": "", "severity": "low"}]},
        {"module": "nikto", "category": "web", "status": "PASS", "severity": "low",
         "summary": "1 finding.",
         "findings": [{"type": "finding", "name": "nikto", "value": "Server leaks inodes via ETags",
                       "detail": "inode etag disclosure", "severity": "low"}]},
    ],
}


def test_offline_by_default():
    f = Flint(api_key=None)
    assert f.online is False


def test_summary_grounded():
    f = Flint(api_key=None)
    s = f.summarize(SCAN)
    assert "localhost:8080" in s
    assert "4 finding" in s or "4 finding(s)" in s


def test_most_critical_picks_sqli():
    f = Flint(api_key=None)
    ans = f.most_critical(SCAN)
    assert "sqlmap" in ans and "critical" in ans


def test_attack_paths_chains_findings():
    f = Flint(api_key=None)
    paths = f.attack_paths(SCAN)
    assert paths
    joined = " ".join(paths).lower()
    assert "sql" in joined  # sqli present -> suggested
    assert "database" in joined  # exposed mysql -> suggested


def test_false_positive_flagging_is_suggestion_only():
    f = Flint(api_key=None)
    before = copy.deepcopy(SCAN)
    fps = f.flag_false_positives(SCAN)
    # nikto ETag/inode entry flagged as noise
    assert any(x["module"] == "nikto" for x in fps)
    # invariant: Flint never mutates the scan / severities
    assert SCAN == before


def test_ask_offline():
    f = Flint(api_key=None)
    assert "sqlmap" in f.ask(SCAN, "what is the most critical issue?")
    assert "4" in f.ask(SCAN, "how many findings?")


def test_invariant_no_severity_mutation():
    """Flint must not assign or change severity anywhere."""
    f = Flint(api_key=None)
    sev_before = [(r["module"], r["severity"], [x["severity"] for x in r["findings"]]) for r in SCAN["results"]]
    f.summarize(SCAN); f.most_critical(SCAN); f.attack_paths(SCAN); f.flag_false_positives(SCAN)
    sev_after = [(r["module"], r["severity"], [x["severity"] for x in r["findings"]]) for r in SCAN["results"]]
    assert sev_before == sev_after
