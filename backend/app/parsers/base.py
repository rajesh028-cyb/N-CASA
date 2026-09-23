"""
N-CASA Base Parser Interface & Models (Pydantic)
=================================================
Abstract base class and data transfer objects for vendor-specific configuration parsing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParserStatusEnum(str, Enum):
    PARSED = "PARSED"
    NOT_PARSED = "NOT_PARSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ParsedEvidenceItem(BaseModel):
    """Line-level evidence for an extracted configuration field."""
    line: int
    text: str
    field: str
    source: str = "parser"


class ParsedConfiguration(BaseModel):
    """Structured vendor-specific representation of a parsed configuration file."""
    file_id: str
    vendor: str
    device_type: str
    status: ParserStatusEnum
    parser: str
    data: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[ParsedEvidenceItem] = Field(default_factory=list)
    unsupported_reason: Optional[str] = None


class AuditParsingSummary(BaseModel):
    """Aggregate summary of all parsed files in an audit."""
    audit_id: str
    status: str
    total_files: int = 0
    parsed_files: int = 0
    unsupported_files: int = 0
    failed_files: int = 0
    files: List[ParsedConfiguration] = Field(default_factory=list)


class BaseParser(ABC):
    """Abstract interface for vendor configuration parsers."""

    @abstractmethod
    def parse(self, file_id: str, content: str, device_type: str, vendor: str) -> ParsedConfiguration:
        """
        Parse raw configuration text into structured vendor data with line-level evidence.
        """
        pass
