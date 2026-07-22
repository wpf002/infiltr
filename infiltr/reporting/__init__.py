"""Report generation: Markdown, self-contained HTML, and PDF."""
from .render import render_markdown, render_html, render_pdf, ReportTheme, PDF_AVAILABLE

__all__ = ["render_markdown", "render_html", "render_pdf", "ReportTheme", "PDF_AVAILABLE"]
