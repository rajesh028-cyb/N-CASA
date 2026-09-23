"""
N-CASA AI Models (Pydantic)
=============================
Structured JSON schemas for AI-assisted unknown-vendor configuration understanding,
evidence cross-checking, confidence estimation, and finding explanations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AIEvidence(BaseModel):
    """Line evidence item linking an AI interpretation back to exact raw config lines."""
    line_start: int
    line_end: int
    text: str
    field: str
    explanation: str


class AIParsedField(BaseModel):
    """Generic AI-derived attribute container with value, confidence score, and line evidence."""
    value: Optional[Any] = None
    confidence: float = 0.0          # 0.00 to 1.00
    evidence: List[AIEvidence] = Field(default_factory=list)
    requires_manual_validation: bool = False


class AIIdentityFields(BaseModel):
    hostname: AIParsedField = Field(default_factory=AIParsedField)


class AIManagementFields(BaseModel):
    ssh_enabled: AIParsedField = Field(default_factory=AIParsedField)
    ssh_version: AIParsedField = Field(default_factory=AIParsedField)
    telnet_enabled: AIParsedField = Field(default_factory=AIParsedField)
    http_enabled: AIParsedField = Field(default_factory=AIParsedField)
    https_enabled: AIParsedField = Field(default_factory=AIParsedField)


class AIAuthenticationFields(BaseModel):
    enable_secret_present: AIParsedField = Field(default_factory=AIParsedField)
    aaa_enabled: AIParsedField = Field(default_factory=AIParsedField)


class AIInterfaceField(BaseModel):
    interface_name: str
    ip_address: AIParsedField = Field(default_factory=AIParsedField)
    enabled: AIParsedField = Field(default_factory=AIParsedField)
    evidence: List[AIEvidence] = Field(default_factory=list)


class AIParsedOutput(BaseModel):
    """Structured output returned by AI provider for unknown configuration analysis."""
    vendor_hypothesis: Dict[str, Any] = Field(
        default_factory=lambda: {"name": "Unknown", "confidence": 0.0, "evidence": []}
    )
    device_type: Dict[str, Any] = Field(
        default_factory=lambda: {"value": "Unknown", "confidence": 0.0, "evidence": []}
    )
    identity: AIIdentityFields = Field(default_factory=AIIdentityFields)
    management: AIManagementFields = Field(default_factory=AIManagementFields)
    authentication: AIAuthenticationFields = Field(default_factory=AIAuthenticationFields)
    interfaces: List[AIInterfaceField] = Field(default_factory=list)
    logging_remote_servers: AIParsedField = Field(default_factory=AIParsedField)
    ntp_servers: AIParsedField = Field(default_factory=AIParsedField)
    raw_json: Optional[Dict[str, Any]] = None


class AIExplanationRecord(BaseModel):
    """Structured AI explanation for a security finding."""
    finding_id: str
    summary: str
    security_impact: str
    evidence_interpretation: str
    recommended_review: str
    confidence: float = 0.90
    evidence: List[AIEvidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AIAnalysisFileResult(BaseModel):
    """Analysis result for a single configuration file."""
    file_id: str
    status: str = "COMPLETED"
    vendor_hypothesis: str = "Unknown"
    confidence: float = 0.0
    parsed_output: Optional[AIParsedOutput] = None
    error: Optional[str] = None


class AIAnalysisSummary(BaseModel):
    """Aggregate AI configuration understanding report for an audit job."""
    audit_id: str
    status: str = "AI_ANALYSIS_COMPLETE"
    enabled: bool = True
    total_files: int = 0
    analyzed_files: int = 0
    files: List[AIAnalysisFileResult] = Field(default_factory=list)
