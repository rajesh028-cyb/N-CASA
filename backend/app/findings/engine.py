"""
N-CASA Findings Engine
========================
Consumes Block 7 compliance results (AuditComplianceSummary), extracts actionable failures
into deduplicated security findings, and aggregates unverified controls into assessment limitations.

Strict Guarantees:
- 100% Deterministic (NO AI, NO LLM)
- Idempotent generation (identical inputs produce identical findings)
- Inherits severity and metadata directly from Block 7 compliance results
- Separates FAIL (findings) from NOT_VERIFIABLE (assessment limitations)
"""

from typing import Dict, List, Set
from app.compliance.models import AuditComplianceSummary, ComplianceStatusEnum, ComplianceResult
from app.findings.models import (
    AssessmentLimitation,
    AuditFindingsSummary,
    FindingEvidence,
    FindingRecord,
    FindingStatusEnum,
    FindingSummaryCounts,
    RemediationStatusEnum,
)


class FindingsEngine:
    """Deterministic findings extraction and deduplication engine."""

    def extract_findings(
        self,
        audit_id: str,
        compliance_summary: AuditComplianceSummary
    ) -> AuditFindingsSummary:
        """
        Extract deduplicated findings and assessment limitations from compliance summary.
        """
        if not compliance_summary or not compliance_summary.results:
            return AuditFindingsSummary(
                audit_id=audit_id,
                status="FINDINGS_COMPLETE",
                summary=FindingSummaryCounts(),
                findings=[],
                assessment_limitations=[],
            )

        failed_results: List[ComplianceResult] = [
            r for r in compliance_summary.results if r.status == ComplianceStatusEnum.FAIL
        ]
        unverifiable_results: List[ComplianceResult] = [
            r for r in compliance_summary.results if r.status == ComplianceStatusEnum.NOT_VERIFIABLE
        ]

        # --- 1. Deduplicate & Group FAIL results into FindingRecords ---
        grouped_failures: Dict[str, List[ComplianceResult]] = {}
        for res in failed_results:
            grouped_failures.setdefault(res.control_id, []).append(res)

        findings: List[FindingRecord] = []
        for control_id, results_list in grouped_failures.items():
            first_res = results_list[0]

            # Aggregate affected files and evidence across all instances of this control failure
            affected_files_set: Set[str] = set()
            evidence_list: List[FindingEvidence] = []

            for res in results_list:
                if getattr(res, "file_id", None):
                    affected_files_set.add(res.file_id)
                for ev in res.evidence:
                    if ev.source_file:
                        affected_files_set.add(ev.source_file)
                    evidence_list.append(
                        FindingEvidence(
                            field=ev.field,
                            value=ev.value,
                            source_file=ev.source_file,
                            source_line=ev.source_line,
                            source_text=ev.source_text,
                            reason=res.observed,
                        )
                    )

            affected_files = sorted(list(affected_files_set)) if affected_files_set else ["inventory_config"]

            # Format deterministic, stable finding ID
            finding_id = f"FND-{audit_id}-{control_id}"

            sev_str = first_res.severity.value if hasattr(first_res.severity, "value") else str(first_res.severity)

            category = first_res.category or self._infer_category(control_id, first_res.framework)

            description = (
                first_res.description
                or f"Security policy violation detected for control {control_id}."
            )

            rationale = (
                first_res.explanation
                or f"Control {control_id} requirement was not satisfied: {first_res.observed}"
            )

            finding = FindingRecord(
                finding_id=finding_id,
                audit_id=audit_id,
                control_id=control_id,
                framework=first_res.framework,
                title=first_res.title,
                description=description,
                severity=sev_str,
                status=FindingStatusEnum.OPEN,
                category=category,
                affected_files=affected_files,
                evidence=evidence_list,
                expected=first_res.expected,
                observed=first_res.observed,
                rationale=rationale,
                vendor=getattr(first_res, "vendor", "") or "",
                device_type=getattr(first_res, "device_type", "") or "",
                file_id=getattr(first_res, "file_id", None),
                remediation_status=RemediationStatusEnum.PENDING_BLOCK_9,
            )
            findings.append(finding)

        # --- 2. Group NOT_VERIFIABLE results into AssessmentLimitations ---
        grouped_unverifiable: Dict[str, List[ComplianceResult]] = {}
        for res in unverifiable_results:
            grouped_unverifiable.setdefault(res.control_id, []).append(res)

        assessment_limitations: List[AssessmentLimitation] = []
        for control_id, results_list in grouped_unverifiable.items():
            first_res = results_list[0]
            affected_files_set = {
                getattr(res, "file_id", None) for res in results_list if getattr(res, "file_id", None)
            } | {
                ev.source_file for res in results_list for ev in res.evidence if ev.source_file
            }
            affected_files_set.discard(None)
            affected_files = sorted(list(affected_files_set)) if affected_files_set else ["inventory_config"]

            limitation = AssessmentLimitation(
                control_id=control_id,
                framework=first_res.framework,
                title=first_res.title,
                description=first_res.description or f"Control {control_id} could not be verified.",
                affected_files=affected_files,
                reason=first_res.observed or "Configuration evidence was incomplete or unparseable.",
            )
            assessment_limitations.append(limitation)

        # --- 3. Compute Summary Metrics ---
        summary_counts = FindingSummaryCounts(
            total_findings=len(findings),
            open=sum(1 for f in findings if f.status == FindingStatusEnum.OPEN),
            resolved=sum(1 for f in findings if f.status == FindingStatusEnum.RESOLVED),
            accepted=sum(1 for f in findings if f.status == FindingStatusEnum.ACCEPTED),
            critical=sum(1 for f in findings if f.severity == "CRITICAL"),
            high=sum(1 for f in findings if f.severity == "HIGH"),
            medium=sum(1 for f in findings if f.severity == "MEDIUM"),
            low=sum(1 for f in findings if f.severity == "LOW"),
            assessment_limitations=len(assessment_limitations),
        )

        return AuditFindingsSummary(
            audit_id=audit_id,
            status="FINDINGS_COMPLETE",
            summary=summary_counts,
            findings=findings,
            assessment_limitations=assessment_limitations,
        )

    @staticmethod
    def _infer_category(control_id: str, framework: str) -> str:
        """Helper to assign a clean categorical bucket based on control ID."""
        cid = control_id.upper()
        if "SSH" in cid or "TELNET" in cid or "HTTP" in cid or "HOST" in cid:
            return "Management Access"
        elif "AUTH" in cid or "SECRET" in cid or "AAA" in cid:
            return "Authentication"
        elif "LOG" in cid:
            return "Logging & Monitoring"
        elif "NTP" in cid or "TIME" in cid:
            return "Time Synchronization"
        elif "FW" in cid or "POLICY" in cid:
            return "Firewall"
        elif "ACL" in cid:
            return "ACL"
        elif "ROUT" in cid:
            return "Routing"
        elif "VPN" in cid:
            return "VPN"
        elif "IF" in cid:
            return "Network Security"
        return "Configuration"


# Global singleton engine instance
findings_engine = FindingsEngine()
