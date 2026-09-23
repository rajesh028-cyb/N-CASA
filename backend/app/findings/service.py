"""
N-CASA Findings Service Layer
================================
Provides in-memory caching, query filtering, and retrieval for findings reports.
"""

from typing import Dict, List, Optional
from app.compliance.models import AuditComplianceSummary
from app.findings.engine import findings_engine
from app.findings.models import AuditFindingsSummary, FindingRecord


class FindingsService:
    """In-memory service managing findings generation and filtering."""

    def generate_findings(
        self,
        audit_id: str,
        compliance_summary: AuditComplianceSummary
    ) -> AuditFindingsSummary:
        """Generate deduplicated findings from compliance summary."""
        return findings_engine.extract_findings(audit_id, compliance_summary)

    def filter_findings(
        self,
        summary: AuditFindingsSummary,
        severity: Optional[str] = None,
        framework: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> AuditFindingsSummary:
        """
        Apply query parameters to filter findings list dynamically.
        """
        filtered = summary.findings

        if severity and severity.upper() != "ALL":
            sev_u = severity.strip().upper()
            filtered = [f for f in filtered if f.severity.upper() == sev_u]

        if framework and framework.upper() != "ALL":
            fw_u = framework.strip().upper()
            filtered = [f for f in filtered if f.framework.upper() == fw_u]

        if status and status.upper() != "ALL":
            st_u = status.strip().upper()
            filtered = [f for f in filtered if f.status.value.upper() == st_u]

        if category and category.upper() != "ALL":
            cat_u = category.strip().lower()
            filtered = [f for f in filtered if cat_u in f.category.lower()]

        return AuditFindingsSummary(
            audit_id=summary.audit_id,
            status=summary.status,
            summary=summary.summary,
            findings=filtered,
            assessment_limitations=summary.assessment_limitations,
        )


findings_service = FindingsService()
