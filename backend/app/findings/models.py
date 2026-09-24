"""
N-CASA Findings Models (Pydantic)
===================================
Models for structured security findings, evidence chains, assessment limitations,
and aggregate audit risk metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingStatusEnum(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"


class RemediationStatusEnum(str, Enum):
    PENDING_BLOCK_9 = "PENDING_BLOCK_9"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class FindingEvidence(BaseModel):
    """Evidence item preserving source line numbers, text, field, and reason."""
    field: str
    value: Optional[Any] = None
    source_file: str
    source_line: Optional[int] = None
    source_text: str
    reason: Optional[str] = None


class FindingRecord(BaseModel):
    """
    Structured security finding extracted from actionable Block 7 compliance failures (FAIL).
    """
    finding_id: str
    audit_id: str
    control_id: str
    framework: str
    title: str
    description: str
    severity: str
    status: FindingStatusEnum = FindingStatusEnum.OPEN
    category: str
    affected_files: List[str] = Field(default_factory=list)
    evidence: List[FindingEvidence] = Field(default_factory=list)
    expected: str
    observed: str
    rationale: str
    vendor: str = ""
    device_type: str = ""
    file_id: Optional[str] = None
    remediation_status: RemediationStatusEnum = RemediationStatusEnum.PENDING_BLOCK_9
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssessmentLimitation(BaseModel):
    """
    Tracks controls that could not be verified (NOT_VERIFIABLE) due to insufficient configuration evidence.
    These are assessment limitations, NOT security findings or confirmed vulnerabilities.
    """
    control_id: str
    framework: str
    title: str
    description: str
    affected_files: List[str] = Field(default_factory=list)
    reason: str


class FindingSummaryCounts(BaseModel):
    """Summary statistics for findings and assessment limitations."""
    total_findings: int = 0
    open: int = 0
    resolved: int = 0
    accepted: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    assessment_limitations: int = 0


class AuditFindingsSummary(BaseModel):
    """Full aggregate findings report for an audit job."""
    audit_id: str
    status: str = "FINDINGS_COMPLETE"
    summary: FindingSummaryCounts = Field(default_factory=FindingSummaryCounts)
    findings: List[FindingRecord] = Field(default_factory=list)
    assessment_limitations: List[AssessmentLimitation] = Field(default_factory=list)
