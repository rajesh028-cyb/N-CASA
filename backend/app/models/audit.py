"""
N-CASA Audit Models (Pydantic)
================================
These are the data-transfer objects (DTOs) used by the API layer.

Block 2:  in-memory metadata only.
Block 11: add SQLAlchemy ORM models alongside these Pydantic schemas.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from app.compliance.models import AuditComplianceSummary
from app.findings.models import AuditFindingsSummary
from app.remediation.models import AuditRemediationSummary
from app.ai.models import AIAnalysisSummary
from app.models.detection import AuditDetectionSummary
from app.models.inventory import AuditInventory
from app.normalization.models import AuditNormalizationSummary
from app.parsers.base import AuditParsingSummary


# ── Audit lifecycle states ────────────────────────────────────────────────────
class AuditStatus(str, Enum):
    """
    Full lifecycle enumeration.
    """
    UPLOADED               = "UPLOADED"
    INGESTING              = "INGESTING"               # Block 3
    READY_FOR_DETECTION    = "READY_FOR_DETECTION"      # Block 3 -> Block 4
    DETECTING              = "DETECTING"               # Block 4
    DETECTION_COMPLETE     = "DETECTION_COMPLETE"      # Block 4
    DETECTION_FAILED       = "DETECTION_FAILED"        # Block 4
    PARSING                = "PARSING"                 # Block 5
    PARSING_COMPLETE       = "PARSING_COMPLETE"        # Block 5
    PARSING_FAILED         = "PARSING_FAILED"          # Block 5
    NORMALIZING            = "NORMALIZING"             # Block 6
    NORMALIZATION_COMPLETE = "NORMALIZATION_COMPLETE"    # Block 6
    NORMALIZATION_FAILED   = "NORMALIZATION_FAILED"      # Block 6
    COMPLIANCE_EVALUATING  = "COMPLIANCE_EVALUATING"     # Block 7
    COMPLIANCE_COMPLETE    = "COMPLIANCE_COMPLETE"       # Block 7
    COMPLIANCE_FAILED      = "COMPLIANCE_FAILED"         # Block 7
    FINDINGS_GENERATING    = "FINDINGS_GENERATING"       # Block 8
    FINDINGS_COMPLETE      = "FINDINGS_COMPLETE"         # Block 8
    FINDINGS_FAILED        = "FINDINGS_FAILED"           # Block 8
    REMEDIATION_GENERATING = "REMEDIATION_GENERATING"    # Block 9
    REMEDIATION_COMPLETE   = "REMEDIATION_COMPLETE"      # Block 9
    REMEDIATION_FAILED     = "REMEDIATION_FAILED"        # Block 9
    AI_ANALYZING           = "AI_ANALYZING"            # Block 10
    AI_ANALYSIS_COMPLETE   = "AI_ANALYSIS_COMPLETE"    # Block 10
    COMPLIANCE_CHECK       = "COMPLIANCE_CHECK"        # Legacy alias
    ANALYZING              = "ANALYZING"               # Block 10
    REMEDIATION_READY      = "REMEDIATION_READY"       # Block 9 alias
    COMPLETED              = "COMPLETED"               # Block 8+
    FAILED                 = "FAILED"


# ── Supported compliance frameworks ──────────────────────────────────────────
class Framework(str, Enum):
    CIS      = "CIS"
    NIST     = "NIST"
    STIG     = "STIG"
    ISO27001 = "ISO27001"   # Extensible — not yet processed


# ── Internal record (stored in the service layer) ─────────────────────────────
class AuditRecord(BaseModel):
    """
    Full internal audit record.
    Block 11: map this to a SQLAlchemy model / PostgreSQL table.
    """
    audit_id:   str
    filename:   str        # Original filename (sanitised, not user path)
    framework:  Framework
    status:     AuditStatus = AuditStatus.UPLOADED
    file_size:  int        # Bytes
    created_at: datetime   = Field(default_factory=lambda: datetime.now(timezone.utc))

    inventory:              Optional[AuditInventory] = None
    detection_summary:      Optional[AuditDetectionSummary] = None
    parsing_summary:        Optional[AuditParsingSummary] = None
    normalization_summary:  Optional[AuditNormalizationSummary] = None
    compliance_summary:     Optional[AuditComplianceSummary] = None
    findings_summary:       Optional[AuditFindingsSummary] = None
    remediation_summary:    Optional[AuditRemediationSummary] = None
    ai_analysis_summary:    Optional[AIAnalysisSummary] = None

    # Reserved for later blocks
    vendor:     Optional[str] = None    # Block 4
    device:     Optional[str] = None    # Block 4
    findings:   int = 0                 # Block 8


# ── API response schemas ──────────────────────────────────────────────────────
class AuditCreateResponse(BaseModel):
    """Returned after a successful POST /api/audits (HTTP 201)."""
    audit_id:  str
    filename:  str
    framework: Framework
    status:    AuditStatus
    file_size: int = 0
    message:   str


class AuditDetailResponse(BaseModel):
    """Returned by GET /api/audits/{audit_id}."""
    audit_id:              str
    filename:              str
    framework:             Framework
    status:                AuditStatus
    created_at:            datetime
    file_size:             int
    inventory:             Optional[AuditInventory] = None
    detection_summary:     Optional[AuditDetectionSummary] = None
    parsing_summary:       Optional[AuditParsingSummary] = None
    normalization_summary: Optional[AuditNormalizationSummary] = None
    compliance_summary:    Optional[AuditComplianceSummary] = None
    findings_summary:       Optional[AuditFindingsSummary] = None
    remediation_summary:    Optional[AuditRemediationSummary] = None
    ai_analysis_summary:    Optional[AIAnalysisSummary] = None
    vendor:                Optional[str] = None
    device:                Optional[str] = None
    findings:              int


class AuditListResponse(BaseModel):
    """Returned by GET /api/audits."""
    items: list[AuditDetailResponse]
    total: int
