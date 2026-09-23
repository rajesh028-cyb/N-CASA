"""
N-CASA Report Service
=====================
Orchestrates report snapshot building, HTML/PDF rendering, storage management, and database persistence.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.repositories.report_repository import ReportRepository
from app.reports.builder import ReportBuilder
from app.reports.html_renderer import HTMLRenderer
from app.reports.pdf_renderer import PDFRenderer
from app.reports.models import AuditReport, ReportMetadata
from app.services.audit_service import audit_service

logger = logging.getLogger("ncasa.report_service")


class ReportService:
    """Singleton service for managing audit security reports."""

    def __init__(self) -> None:
        reports_dir = getattr(settings, "REPORTS_DIR", "storage/reports")
        self._reports_root = Path(reports_dir).resolve()
        self._reports_root.mkdir(parents=True, exist_ok=True)
        self.html_renderer = HTMLRenderer()
        self.pdf_renderer = PDFRenderer()

    def _get_audit_report_dir(self, audit_id: str) -> Path:
        """Return audit-specific storage directory."""
        dir_path = (self._reports_root / audit_id).resolve()
        # Security Path Traversal Validation
        if not str(dir_path).startswith(str(self._reports_root.resolve())):
            raise ValueError(f"Path traversal detected for audit_id: {audit_id}")
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    async def generate_report(self, audit_id: str) -> ReportMetadata:
        """Generate, render, store, and persist a new report snapshot for an audit."""
        audit = await audit_service.get_audit(audit_id)
        if not audit:
            raise KeyError(f"Audit '{audit_id}' not found.")

        # Require compliance data to be available
        if not audit.compliance_summary:
            raise ValueError(f"Audit '{audit_id}' cannot generate a report before compliance evaluation is completed.")

        # Build Snapshot Model
        report_id = ReportBuilder.generate_report_id()
        snapshot = ReportBuilder.build(audit, report_id=report_id)

        # Render HTML
        html_content = self.html_renderer.render(snapshot)

        # Render PDF
        pdf_bytes = self.pdf_renderer.render_html_to_pdf(html_content)

        # File Storage
        audit_dir = self._get_audit_report_dir(audit_id)
        html_file = audit_dir / f"N-CASA-{report_id}.html"
        pdf_file = audit_dir / f"N-CASA-{report_id}.pdf"

        html_file.write_text(html_content, encoding="utf-8")
        pdf_file.write_bytes(pdf_bytes)

        # Database Persistence
        async with AsyncSessionLocal() as session:
            repo = ReportRepository(session)
            db_report = await repo.create_report(
                report_id=report_id,
                audit_id=audit_id,
                html_path=str(html_file),
                pdf_path=str(pdf_file),
                report_version="1.0",
            )
            await session.commit()

        logger.info("Report %s generated for audit %s -> HTML & PDF saved", report_id, audit_id)
        return ReportMetadata(
            report_id=report_id,
            audit_id=audit_id,
            generated_at=db_report.generated_at,
            report_version="1.0",
            html_path=str(html_file),
            pdf_path=str(pdf_file),
        )

    async def list_reports(self, audit_id: str) -> List[ReportMetadata]:
        """Retrieve all generated reports for an audit."""
        async with AsyncSessionLocal() as session:
            repo = ReportRepository(session)
            reports = await repo.get_reports_for_audit(audit_id)
            return [
                ReportMetadata(
                    report_id=r.report_id,
                    audit_id=r.audit_id,
                    generated_at=r.generated_at,
                    report_version=r.report_version,
                    html_path=r.html_path,
                    pdf_path=r.pdf_path,
                )
                for r in reports
            ]

    async def get_report_metadata(self, audit_id: str, report_id: str) -> Optional[ReportMetadata]:
        """Get report metadata by ID."""
        async with AsyncSessionLocal() as session:
            repo = ReportRepository(session)
            r = await repo.get_report_by_id(audit_id, report_id)
            if not r:
                return None
            return ReportMetadata(
                report_id=r.report_id,
                audit_id=r.audit_id,
                generated_at=r.generated_at,
                report_version=r.report_version,
                html_path=r.html_path,
                pdf_path=r.pdf_path,
            )

    async def get_report_file_path(self, audit_id: str, report_id: str, fmt: str) -> Path:
        """Return safe path to HTML or PDF report file."""
        if ".." in audit_id or "/" in audit_id or "\\" in audit_id or ".." in report_id:
            raise ValueError("Path traversal violation detected in parameters.")
        fmt = fmt.lower()
        if fmt not in ("html", "pdf"):
            raise ValueError("Format must be 'html' or 'pdf'.")

        meta = await self.get_report_metadata(audit_id, report_id)
        if not meta:
            raise KeyError(f"Report '{report_id}' not found for audit '{audit_id}'.")

        target_path = Path(meta.html_path if fmt == "html" else meta.pdf_path).resolve()

        # Security Path Traversal Validation
        if not str(target_path).startswith(str(self._reports_root.resolve())):
            raise ValueError("Path traversal violation detected.")

        if not target_path.exists():
            raise FileNotFoundError(f"Report {fmt.upper()} file missing from storage.")

        return target_path


report_service = ReportService()
