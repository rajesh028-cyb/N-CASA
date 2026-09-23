"""
N-CASA Report SQLAlchemy ORM Model
====================================
Maps persistent generated security report metadata in PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.audit import AuditModel


class ReportModel(Base):
    """Stores metadata for generated N-CASA audit reports."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    report_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    audit_id: Mapped[str] = mapped_column(String, ForeignKey("audits.audit_id", ondelete="CASCADE"), index=True, nullable=False)

    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    report_version: Mapped[str] = mapped_column(String, default="1.0", nullable=False)

    html_path: Mapped[str] = mapped_column(String, nullable=False)
    pdf_path: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship back to parent audit
    audit: Mapped["AuditModel"] = relationship("AuditModel", back_populates="reports")
