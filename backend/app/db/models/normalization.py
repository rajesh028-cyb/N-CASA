"""
N-CASA Database Model — Normalized Configuration
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class NormalizedConfigurationModel(Base):
    __tablename__ = "normalized_configurations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    file_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    normalization_method: Mapped[str] = mapped_column(String(64), nullable=False, default="DETERMINISTIC")
    requires_manual_validation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    normalized_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
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

    audit = relationship("AuditModel", back_populates="normalized_configs")
