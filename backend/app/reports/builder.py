"""
N-CASA Report Builder
=====================
Constructs an AuditReport snapshot from persisted PostgreSQL database repositories.
Sanitizes sensitive values (passwords, PSKs, community strings, private keys) with <REDACTED>.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.reports.models import AuditReport
from app.models.audit import AuditRecord


# Secret Sanitization Patterns
SECRET_PATTERNS = [
    # Cisco / Juniper / Fortinet password, secret, PSK, community lines
    (re.compile(r'(?i)\b(password|secret|enable\s+secret|pre-shared-key|psk|md5-key|community)\s+.*$', re.MULTILINE), r'\1 <REDACTED>'),
    # Private Key blocks
    (re.compile(r'-----BEGIN\s+.*?\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+.*?\s+PRIVATE\s+KEY-----', re.IGNORECASE), r'<REDACTED PRIVATE KEY>'),
]


def redact_secrets_text(text: str) -> str:
    """Sanitize secret values from configuration and evidence text snippets."""
    if not text or not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_secrets_obj(obj: Any) -> Any:
    """Recursively scrub secrets from dicts, lists, and strings."""
    if isinstance(obj, str):
        return redact_secrets_text(obj)
    elif isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            if k.lower() in ("password", "secret", "psk", "private_key", "api_key", "token", "community"):
                new_dict[k] = "<REDACTED>"
            else:
                new_dict[k] = redact_secrets_obj(v)
        return new_dict
    elif isinstance(obj, list):
        return [redact_secrets_obj(item) for item in obj]
    return obj


class ReportBuilder:
    """
    Assembles a complete AuditReport snapshot from an AuditRecord instance.
    """

    @staticmethod
    def generate_report_id() -> str:
        """Generate public report ID format: RPT-AUD-YYYYMMDD-XXXX"""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        rand_str = uuid.uuid4().hex[:4].upper()
        return f"RPT-AUD-{date_str}-{rand_str}"

    @classmethod
    def build(cls, audit: AuditRecord, report_id: Optional[str] = None) -> AuditReport:
        """Construct AuditReport snapshot from AuditRecord."""
        if not report_id:
            report_id = cls.generate_report_id()

        # Audit Metadata
        audit_meta = {
            "audit_id": audit.audit_id,
            "filename": audit.filename,
            "framework": audit.framework.value if hasattr(audit.framework, "value") else str(audit.framework),
            "status": audit.status.value if hasattr(audit.status, "value") else str(audit.status),
            "created_at": audit.created_at.isoformat() if hasattr(audit.created_at, "isoformat") else str(audit.created_at),
            "vendor": audit.vendor or "UNKNOWN",
            "device": audit.device or "Unknown",
        }

        # Inventory Summary & Files
        inv_summary = {}
        inv_files = []
        if audit.inventory:
            inv_summary = {
                "total_files_discovered": audit.inventory.total_files_discovered,
                "valid_configs_count": audit.inventory.valid_configs_count,
                "total_lines": audit.inventory.total_lines,
            }
            for f in audit.inventory.files:
                inv_files.append(redact_secrets_obj(f.model_dump() if hasattr(f, "model_dump") else dict(f)))

        # Device & Detection Summary
        dev_summary = {}
        dev_list = []
        if audit.detection_summary:
            dev_summary = {
                "total_files": audit.detection_summary.total_files,
                "detected_files": audit.detection_summary.detected_files,
                "status": audit.detection_summary.status,
            }
            for d in audit.detection_summary.files:
                dev_list.append(redact_secrets_obj(d.model_dump() if hasattr(d, "model_dump") else dict(d)))

        # Parsing & Normalization
        parse_summary = {}
        if audit.parsing_summary:
            parse_summary = redact_secrets_obj(audit.parsing_summary.model_dump() if hasattr(audit.parsing_summary, "model_dump") else dict(audit.parsing_summary))

        norm_summary = {}
        if audit.normalization_summary:
            norm_summary = redact_secrets_obj(audit.normalization_summary.model_dump() if hasattr(audit.normalization_summary, "model_dump") else dict(audit.normalization_summary))

        # Compliance Breakdown
        comp_summary = {}
        comp_results = []
        if audit.compliance_summary:
            c_dict = audit.compliance_summary.model_dump() if hasattr(audit.compliance_summary, "model_dump") else dict(audit.compliance_summary)
            comp_summary = redact_secrets_obj(c_dict)

            # Compute framework & status counts for compliance breakdown tables
            pass_cnt = 0
            fail_cnt = 0
            not_verifiable_cnt = 0
            framework_counts = {}
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

            if audit.compliance_summary.results:
                for r in audit.compliance_summary.results:
                    r_dict = redact_secrets_obj(r.model_dump() if hasattr(r, "model_dump") else dict(r))
                    comp_results.append(r_dict)

                    st = r_dict.get("status", "PASS")
                    if st == "PASS":
                        pass_cnt += 1
                    elif st == "FAIL":
                        fail_cnt += 1
                    else:
                        not_verifiable_cnt += 1

                    fw = r_dict.get("framework", "CIS")
                    if fw not in framework_counts:
                        framework_counts[fw] = {"PASS": 0, "FAIL": 0, "NOT_VERIFIABLE": 0}
                    if st in framework_counts[fw]:
                        framework_counts[fw][st] += 1

                    sev = str(r_dict.get("severity", "LOW")).upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1

            comp_summary.update({
                "total_controls": len(comp_results),
                "pass_count": pass_cnt,
                "fail_count": fail_cnt,
                "not_verifiable_count": not_verifiable_cnt,
                "framework_counts": framework_counts,
                "severity_counts": severity_counts,
            })

        # Findings & Assessment Limitations
        findings_list = []
        limitations_list = []
        if audit.findings_summary:
            if audit.findings_summary.findings:
                for f in audit.findings_summary.findings:
                    findings_list.append(redact_secrets_obj(f.model_dump() if hasattr(f, "model_dump") else dict(f)))
            if audit.findings_summary.assessment_limitations:
                for l in audit.findings_summary.assessment_limitations:
                    limitations_list.append(redact_secrets_obj(l.model_dump() if hasattr(l, "model_dump") else dict(l)))

        # Remediations
        rem_summary = {}
        rem_proposals = []
        if audit.remediation_summary:
            rem_summary = {
                "remediations_available": audit.remediation_summary.summary.remediations_available if hasattr(audit.remediation_summary, "summary") else 0,
                "status": audit.remediation_summary.status,
            }
            if audit.remediation_summary.remediations:
                for r in audit.remediation_summary.remediations:
                    rem_proposals.append(redact_secrets_obj(r.model_dump() if hasattr(r, "model_dump") else dict(r)))

        # AI Analysis
        ai_summary = None
        ai_exps = []
        if audit.ai_analysis_summary:
            ai_summary = redact_secrets_obj(audit.ai_analysis_summary.model_dump() if hasattr(audit.ai_analysis_summary, "model_dump") else dict(audit.ai_analysis_summary))

        return AuditReport(
            report_id=report_id,
            audit_id=audit.audit_id,
            generated_at=datetime.now(timezone.utc),
            report_version="1.0",
            audit_metadata=audit_meta,
            inventory_summary=inv_summary,
            files=inv_files,
            device_summary=dev_summary,
            devices=dev_list,
            parsing_summary=parse_summary,
            normalization_summary=norm_summary,
            compliance_summary=comp_summary,
            compliance_results=comp_results,
            findings=findings_list,
            assessment_limitations=limitations_list,
            remediation_summary=rem_summary,
            remediation_proposals=rem_proposals,
            ai_analysis_summary=ai_summary,
            ai_explanations=ai_exps,
        )
