"""
N-CASA Deterministic Compliance Models (Pydantic)
===================================================
Models for control definitions, evaluation results, framework filtering,
and evidence-driven compliance assessments.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ComplianceStatusEnum(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class ComplianceSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ComplianceEvidence(BaseModel):
    """Normalized evidence item supporting a compliance result."""
    field: str
    value: Optional[Any] = None
    source_file: str
    source_line: Optional[int] = None
    source_text: str


class ControlMetadata(BaseModel):
    """Metadata schema for a security control in the control catalog."""
    control_id: str
    framework: str        # CIS | NIST | STIG
    title: str
    description: str
    severity: ComplianceSeverityEnum
    category: str
    rule: str
    internal_mapping: bool = True   # Marks internal mapping IDs vs official standards


class ComplianceResult(BaseModel):
    """Result of evaluating a single compliance control on a configuration."""
    control_id: str
    framework: str
    title: str
    description: Optional[str] = None
    severity: ComplianceSeverityEnum
    category: Optional[str] = None
    status: ComplianceStatusEnum
    expected: str
    observed: str
    explanation: Optional[str] = None
    evidence: List[ComplianceEvidence] = Field(default_factory=list)
    rule: str
    internal_mapping: bool = True
    file_id: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None


class ComplianceSummaryCounts(BaseModel):
    """Aggregate result counts across controls."""
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    not_verifiable: int = 0


class ComplianceSeverityCounts(BaseModel):
    """Breakdown of controls by severity."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AuditComplianceSummary(BaseModel):
    """Full aggregate compliance report for an audit."""
    audit_id: str
    status: str = "COMPLIANCE_COMPLETE"
    framework_filter: Optional[str] = None
    files_evaluated: int = 0
    summary: ComplianceSummaryCounts = Field(default_factory=ComplianceSummaryCounts)
    severity_counts: ComplianceSeverityCounts = Field(default_factory=ComplianceSeverityCounts)
    results: List[ComplianceResult] = Field(default_factory=list)
