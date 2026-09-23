"""
N-CASA Findings Engine Module
===============================
Block 8: Converts Block 7 compliance results into structured, deduplicated security findings
and assessment limitations.
"""

from app.findings.models import (
    AssessmentLimitation,
    AuditFindingsSummary,
    FindingEvidence,
    FindingRecord,
    FindingStatusEnum,
    FindingSummaryCounts,
    RemediationStatusEnum,
)
from app.findings.engine import findings_engine, FindingsEngine
from app.findings.service import findings_service, FindingsService

__all__ = [
    "AssessmentLimitation",
    "AuditFindingsSummary",
    "FindingEvidence",
    "FindingRecord",
    "FindingStatusEnum",
    "FindingSummaryCounts",
    "RemediationStatusEnum",
    "findings_engine",
    "FindingsEngine",
    "findings_service",
    "FindingsService",
]
