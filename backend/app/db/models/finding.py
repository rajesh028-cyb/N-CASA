"""
N-CASA Database Models — Findings & Assessment Limitations
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Integer, DateTime, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("audit_id", "finding_id", name="uq_audit_finding"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    control_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    expected: Mapped[str] = mapped_column(String(512), nullable=False)
    observed: Mapped[str] = mapped_column(String(512), nullable=False)
    rationale: Mapped[str] = mapped_column(String(1024), nullable=False)
    remediation_status: Mapped[str] = mapped_column(String(64), nullable=False, default="NOT_REMEDIATED")
    affected_files: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    evidence: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    audit = relationship("AuditModel", back_populates="findings")


class AssessmentLimitationModel(Base):
    __tablename__ = "assessment_limitations"

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
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    affected_files: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    audit = relationship("AuditModel", back_populates="limitations")
