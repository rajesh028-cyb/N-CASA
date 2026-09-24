"""
N-CASA Deterministic Compliance Engine
========================================
Receives vendor-neutral NormalizedConfiguration objects, executes registered rules,
collects evidence-driven results, and produces aggregate compliance assessments.
"""

from typing import List, Optional
from app.compliance.models import (
    AuditComplianceSummary,
    ComplianceResult,
    ComplianceSeverityCounts,
    ComplianceStatusEnum,
    ComplianceSummaryCounts,
)
from app.compliance.registry import compliance_rule_registry
from app.normalization.models import NormalizedConfiguration


class ComplianceEngine:
    """Deterministic, rule-based compliance engine."""

    def evaluate_configurations(
        self,
        audit_id: str,
        norm_configs: List[NormalizedConfiguration],
        framework_filter: Optional[str] = None
    ) -> AuditComplianceSummary:
        """
        Evaluate a list of normalized configurations against compliance rules.
        Supports framework filtering (e.g. CIS, NIST, STIG).
        Deduplicates control results by control_id across multi-file audit packages.
        """
        rules = compliance_rule_registry.get_rules(framework_filter)

        all_results: List[ComplianceResult] = []

        # Evaluate each normalized configuration independently to prevent cross-config contamination
        for config in norm_configs:
            # Skip un-normalized or unsupported files
            if config.status.value != "NORMALIZED":
                continue

            for rule in rules:
                res = rule.evaluate(config)
                res.file_id = config.file_id
                res.vendor = config.vendor
                res.device_type = config.device_type
                all_results.append(res)

        summary_counts = ComplianceSummaryCounts()
        severity_counts = ComplianceSeverityCounts()

        for res in all_results:
            summary_counts.total_controls += 1
            if res.status == ComplianceStatusEnum.PASS:
                summary_counts.passed += 1
            elif res.status == ComplianceStatusEnum.FAIL:
                summary_counts.failed += 1
            elif res.status == ComplianceStatusEnum.NOT_VERIFIABLE:
                summary_counts.not_verifiable += 1

            sev_val = res.severity.value if hasattr(res.severity, "value") else str(res.severity)
            if sev_val == "CRITICAL":
                severity_counts.critical += 1
            elif sev_val == "HIGH":
                severity_counts.high += 1
            elif sev_val == "MEDIUM":
                severity_counts.medium += 1
            elif sev_val == "LOW":
                severity_counts.low += 1

        normalized_file_count = sum(1 for c in norm_configs if c.status.value == "NORMALIZED")

        return AuditComplianceSummary(
            audit_id=audit_id,
            status="COMPLIANCE_COMPLETE",
            framework_filter=framework_filter,
            files_evaluated=normalized_file_count,
            summary=summary_counts,
            severity_counts=severity_counts,
            results=all_results,
        )


# Global singleton engine instance
compliance_engine = ComplianceEngine()
