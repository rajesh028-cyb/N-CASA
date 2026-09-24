"""
N-CASA HTML Report Renderer
===========================
Renders structured AuditReport snapshot into a professional HTML security audit report via Jinja2.
"""

from __future__ import annotations

from pathlib import Path
import jinja2

from app.reports.models import AuditReport

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class HTMLRenderer:
    """Renders AuditReport models into standalone HTML files."""

    def __init__(self) -> None:
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )
        self.template = self.env.get_template("report.html")

    def render(self, report: AuditReport) -> str:
        """Render AuditReport model into HTML string."""
        report_dict = report.model_dump() if hasattr(report, "model_dump") else dict(report)
        return self.template.render(report=report, data=report_dict)
