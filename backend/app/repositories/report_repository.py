"""
N-CASA Report Repository
========================
Data access layer for report metadata in PostgreSQL via SQLAlchemy 2.x async session.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.report import ReportModel


class ReportRepository:
    """Repository for managing ReportModel persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_report(
        self,
        report_id: str,
        audit_id: str,
        html_path: str,
        pdf_path: str,
        report_version: str = "1.0",
    ) -> ReportModel:
        """Create and persist a new report metadata entry."""
        report = ReportModel(
            report_id=report_id,
            audit_id=audit_id,
            generated_at=datetime.now(timezone.utc),
            report_version=report_version,
            html_path=html_path,
            pdf_path=pdf_path,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(report)
        await self.session.flush()
        return report

    async def get_reports_for_audit(self, audit_id: str) -> List[ReportModel]:
        """Retrieve all generated reports for a given audit, sorted newest first."""
        stmt = (
            select(ReportModel)
            .where(ReportModel.audit_id == audit_id)
            .order_by(ReportModel.generated_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_report_by_id(self, audit_id: str, report_id: str) -> Optional[ReportModel]:
        """Retrieve a specific report by audit_id and report_id."""
        stmt = select(ReportModel).where(
            ReportModel.audit_id == audit_id,
            ReportModel.report_id == report_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
