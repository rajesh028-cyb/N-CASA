"""
N-CASA Database Model — Compliance Results
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class ComplianceResultModel(Base):
    __tablename__ = "compliance_results"
    __table_args__ = (
        UniqueConstraint("audit_id", "control_id", "file_id", name="uq_audit_control_file"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    control_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    expected: Mapped[str] = mapped_column(String(512), nullable=False)
    observed: Mapped[str] = mapped_column(String(512), nullable=False)
    rationale: Mapped[str] = mapped_column(String(1024), nullable=False)
    internal_mapping: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    file_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    vendor: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    audit = relationship("AuditModel", back_populates="compliance_results")
