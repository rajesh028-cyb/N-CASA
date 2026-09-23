"""
N-CASA Remediation Models (Pydantic)
======================================
Models for vendor-specific remediation suggestions, validation steps,
review metadata, and aggregate remediation reporting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RemediationStatusEnum(str, Enum):
    AVAILABLE = "AVAILABLE"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ReviewStatusEnum(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    REVIEWED = "REVIEWED"


class RemediationRecord(BaseModel):
    """
    Proposed configuration remediation suggestion for an actionable security finding.
    GUARANTEE: Proposed configuration ONLY — NO automatic device execution.
    """
    remediation_id: str
    finding_id: str
    audit_id: str

    control_id: str
    framework: str

    vendor: str
    device_type: str

    title: str
    description: str

    status: RemediationStatusEnum = RemediationStatusEnum.AVAILABLE
    review_status: ReviewStatusEnum = ReviewStatusEnum.PENDING_REVIEW

    proposed_commands: List[str] = Field(default_factory=list)
    current_configuration: Optional[str] = None
    proposed_configuration: str = ""

    validation_steps: List[str] = Field(default_factory=list)
    rollback_guidance: Optional[str] = None

    affected_files: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)

    manual_review_required: bool = False
    required_inputs: List[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationSummaryCounts(BaseModel):
    """Summary metrics for remediation proposals."""
    total_findings: int = 0
    remediations_available: int = 0
    manual_review_required: int = 0
    not_available: int = 0
    pending_review: int = 0
    reviewed: int = 0


class AuditRemediationSummary(BaseModel):
    """Full aggregate remediation report for an audit job."""
    audit_id: str
    status: str = "REMEDIATION_COMPLETE"
    summary: RemediationSummaryCounts = Field(default_factory=RemediationSummaryCounts)
    remediations: List[RemediationRecord] = Field(default_factory=list)
