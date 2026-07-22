"""Report rendering: markdown + self-contained HTML from a scan dict."""
from infiltr.reporting import render_markdown, render_html, ReportTheme


SCAN = {
    "id": 7,
    "target": "http://localhost:8080",
    "started_at": "2026-07-21T12:00:00+00:00",
    "module_count": 2,
    "finding_count": 3,
    "top_severity": "critical",
    "results": [
        {
            "module": "sqlmap", "category": "web", "status": "PASS", "severity": "critical",
            "duration": 4.2, "summary": "1 injectable point.", "command": "sqlmap -u ...",
            "findings": [
                {"type": "sqli", "name": "injectable parameter", "value": "id",
                 "detail": "boolean-based blind", "severity": "critical"},
            ],
        },
        {
            "module": "nmap", "category": "recon", "status": "PASS", "severity": "medium",
            "duration": 3.0, "summary": "2 open ports.", "command": "nmap ...",
            "findings": [
                {"type": "open_port", "name": "80/tcp", "value": "http", "detail": "", "severity": "low"},
                {"type": "open_port", "name": "3306/tcp", "value": "mysql", "detail": "", "severity": "medium"},
            ],
        },
    ],
}


def test_markdown_report():
    md = render_markdown(SCAN, ReportTheme(client="ACME Corp"))
    assert "# Infiltr Security Scan Report" in md
    assert "ACME Corp" in md
    assert "http://localhost:8080" in md
    assert "| Critical | 1 |" in md
    assert "injectable parameter" in md
    # critical module sorted before medium
    assert md.index("### sqlmap") < md.index("### nmap")


def test_html_report_self_contained():
    h = render_html(SCAN, ReportTheme(brand="Infiltr", client="ACME"))
    assert h.startswith("<!DOCTYPE html>")
    assert "<style>" in h and "http" not in h.split("<style>")[1].split("</style>")[0].replace("://", "")  # no external URLs in CSS
    assert "sqlmap" in h and "nmap" in h
    assert "ACME" in h
    # severity colors present
    assert "#b366ff" in h  # critical


def test_html_escapes_content():
    scan = dict(SCAN)
    scan["target"] = "http://x/<script>alert(1)</script>"
    h = render_html(scan)
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h
