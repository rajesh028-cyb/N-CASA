"""
N-CASA Database Model — Remediation Proposal
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Integer, Boolean, DateTime, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class RemediationModel(Base):
    __tablename__ = "remediations"
    __table_args__ = (
        UniqueConstraint("audit_id", "remediation_id", name="uq_audit_remediation"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    remediation_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    control_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    vendor: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    device_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="PROPOSED")
    review_status: Mapped[str] = mapped_column(String(64), nullable=False, default="PENDING")
    proposed_commands: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    current_configuration: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    proposed_configuration: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    validation_steps: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    rollback_guidance: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    affected_files: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    evidence: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    manual_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    required_inputs: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
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

    audit = relationship("AuditModel", back_populates="remediations")
