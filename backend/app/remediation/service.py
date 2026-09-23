"""
N-CASA Remediation Service Layer
==================================
Provides in-memory caching, query filtering, and human review status updates.
"""

from typing import Dict, List, Optional
from app.findings.models import AuditFindingsSummary
from app.remediation.engine import remediation_engine
from app.remediation.models import (
    AuditRemediationSummary,
    RemediationRecord,
    RemediationStatusEnum,
    ReviewStatusEnum,
)


class RemediationService:
    """In-memory service managing remediation generation, filtering, and review states."""

    def generate_remediations(
        self,
        audit_id: str,
        findings_summary: AuditFindingsSummary,
        vendor_map: Optional[Dict[str, str]] = None
    ) -> AuditRemediationSummary:
        """Generate vendor-specific remediation suggestions."""
        return remediation_engine.generate_remediations(audit_id, findings_summary, vendor_map)

    def filter_remediations(
        self,
        summary: AuditRemediationSummary,
        vendor: Optional[str] = None,
        status: Optional[str] = None,
        review_status: Optional[str] = None,
    ) -> AuditRemediationSummary:
        """Apply query filters to remediation report."""
        filtered = summary.remediations

        if vendor and vendor.upper() != "ALL":
            v_u = vendor.strip().upper()
            filtered = [r for r in filtered if r.vendor.upper() == v_u]

        if status and status.upper() != "ALL":
            st_u = status.strip().upper()
            filtered = [r for r in filtered if r.status.value.upper() == st_u]

        if review_status and review_status.upper() != "ALL":
            rst_u = review_status.strip().upper()
            filtered = [r for r in filtered if r.review_status.value.upper() == rst_u]

        return AuditRemediationSummary(
            audit_id=summary.audit_id,
            status=summary.status,
            summary=summary.summary,
            remediations=filtered,
        )

    def mark_reviewed(
        self,
        summary: AuditRemediationSummary,
        remediation_id: str
    ) -> Optional[RemediationRecord]:
        """Update review status of a remediation proposal to REVIEWED."""
        rem_id_upper = remediation_id.strip().upper()
        target = next((r for r in summary.remediations if r.remediation_id.upper() == rem_id_upper), None)
        if not target:
            return None

        target.review_status = ReviewStatusEnum.REVIEWED

        # Recalculate summary counts
        summary.summary.pending_review = sum(
            1 for r in summary.remediations if r.review_status == ReviewStatusEnum.PENDING_REVIEW
        )
        summary.summary.reviewed = sum(
            1 for r in summary.remediations if r.review_status == ReviewStatusEnum.REVIEWED
        )

        return target


remediation_service = RemediationService()
