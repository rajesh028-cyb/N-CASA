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

        results_by_control: dict[str, ComplianceResult] = {}

        # If multiple files exist in audit, evaluate rules across normalized configs
        for config in norm_configs:
            # Skip un-normalized or unsupported files
            if config.status.value != "NORMALIZED":
                continue

            for rule in rules:
                res = rule.evaluate(config)
                cid = res.control_id

                if cid not in results_by_control:
                    results_by_control[cid] = res
                else:
                    existing = results_by_control[cid]
                    # If any file fails the control requirement, the control status is FAIL for the audit
                    if res.status == ComplianceStatusEnum.FAIL:
                        existing.status = ComplianceStatusEnum.FAIL
                        existing.observed = f"{existing.observed}; {res.observed}" if existing.observed != res.observed else existing.observed
                        res_exp = getattr(res, "explanation", getattr(res, "rationale", None))
                        exist_exp = getattr(existing, "explanation", getattr(existing, "rationale", "")) or ""
                        if res_exp and res_exp not in exist_exp:
                            if hasattr(existing, "explanation"):
                                existing.explanation = f"{exist_exp}\n{res_exp}".strip()
                            elif hasattr(existing, "rationale"):
                                existing.rationale = f"{exist_exp}\n{res_exp}".strip()
                    elif res.status == ComplianceStatusEnum.PASS and existing.status == ComplianceStatusEnum.NOT_VERIFIABLE:
                        existing.status = ComplianceStatusEnum.PASS
                        existing.observed = res.observed

                    # Merge evidence items
                    existing_ev_keys = {(ev.source_file, ev.source_line) for ev in (existing.evidence or [])}
                    for ev in (res.evidence or []):
                        if (ev.source_file, ev.source_line) not in existing_ev_keys:
                            existing.evidence.append(ev)
                            existing_ev_keys.add((ev.source_file, ev.source_line))

        all_results: List[ComplianceResult] = list(results_by_control.values())

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
