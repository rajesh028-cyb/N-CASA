"""
N-CASA Database Model — Parsed Configuration
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class ParsedConfigurationModel(Base):
    __tablename__ = "parsed_configurations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    file_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    parsed_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    audit = relationship("AuditModel", back_populates="parsed_configs")
