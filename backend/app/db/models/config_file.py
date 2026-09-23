"""
N-CASA Database Model — Configuration File
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class ConfigFileModel(Base):
    __tablename__ = "audit_config_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    audit_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("audits.audit_id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    relative_path: Mapped[str] = mapped_column(String(512), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    line_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    non_empty_line_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    comment_line_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    candidate_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    encoding: Mapped[str] = mapped_column(String(64), nullable=False, default="utf-8")
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="DISCOVERED")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationship
    audit = relationship("AuditModel", back_populates="config_files")
