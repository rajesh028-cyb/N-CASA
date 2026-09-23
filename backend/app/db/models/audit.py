"""
N-CASA Database Model — Audit
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class AuditModel(Base):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    compliance_framework: Mapped[str] = mapped_column(String(64), nullable=False, default="CIS")
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inventory: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    detection_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ai_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    config_files = relationship("ConfigFileModel", back_populates="audit", cascade="all, delete-orphan")
    detections = relationship("VendorDetectionModel", back_populates="audit", cascade="all, delete-orphan")
    parsed_configs = relationship("ParsedConfigurationModel", back_populates="audit", cascade="all, delete-orphan")
    normalized_configs = relationship("NormalizedConfigurationModel", back_populates="audit", cascade="all, delete-orphan")
    compliance_results = relationship("ComplianceResultModel", back_populates="audit", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="audit", cascade="all, delete-orphan")
    limitations = relationship("AssessmentLimitationModel", back_populates="audit", cascade="all, delete-orphan")
    remediations = relationship("RemediationModel", back_populates="audit", cascade="all, delete-orphan")
    ai_results = relationship("AIAnalysisResultModel", back_populates="audit", cascade="all, delete-orphan")
    ai_explanations = relationship("AIExplanationModel", back_populates="audit", cascade="all, delete-orphan")
    reports = relationship("ReportModel", back_populates="audit", cascade="all, delete-orphan")
