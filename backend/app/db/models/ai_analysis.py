"""
N-CASA Database Models — AI Analysis Results & AI Explanations
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class AIAnalysisResultModel(Base):
    __tablename__ = "ai_analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    file_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    analysis_method: Mapped[str] = mapped_column(String(64), nullable=False)
    vendor_hypothesis: Mapped[str] = mapped_column(String(64), nullable=False)
    device_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    normalized_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    requires_manual_validation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    audit = relationship("AuditModel", back_populates="ai_results")


class AIExplanationModel(Base):
    __tablename__ = "ai_explanations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    finding_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    summary: Mapped[str] = mapped_column(String(1024), nullable=False)
    security_impact: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence_interpretation: Mapped[str] = mapped_column(String(2048), nullable=False)
    recommended_review: Mapped[str] = mapped_column(String(2048), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    audit = relationship("AuditModel", back_populates="ai_explanations")
