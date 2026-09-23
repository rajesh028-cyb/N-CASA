"""
N-CASA Fortinet FortiOS Remediation Templates
================================================
Deterministic remediation proposals for Fortinet FortiOS interface & system configurations.
"""

from typing import List
from app.findings.models import FindingRecord
from app.remediation.models import RemediationRecord, RemediationStatusEnum, ReviewStatusEnum
from app.remediation.templates.base import BaseRemediationTemplate


class FortinetTelnetRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-TELNET-001"
    vendor = "Fortinet"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        interface_name = "port1"
        allowed = ["ping", "ssh", "https"]

        if finding.evidence:
            for ev in finding.evidence:
                if "allowaccess" in ev.source_text.lower():
                    # Parse existing allowed services and strip telnet
                    parts = ev.source_text.strip().split()
                    existing_services = [p for p in parts if p.lower() not in ["set", "allowaccess", "telnet"]]
                    if existing_services:
                        allowed = existing_services

        allowed_str = " ".join(allowed)
        cmds = [
            "config system interface",
            f"edit {interface_name}",
            f"set allowaccess {allowed_str}",
            "next",
            "end",
        ]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Firewall / Security Appliance",
            title="Remove Telnet from Interface Allowaccess",
            description="Update FortiOS interface management access list to remove Telnet while preserving SSH and HTTPS.",
            status=RemediationStatusEnum.AVAILABLE,
            review_status=ReviewStatusEnum.PENDING_REVIEW,
            proposed_commands=cmds,
            current_configuration=finding.observed,
            proposed_configuration="\n".join(cmds),
            validation_steps=self._default_validation_steps(self.control_id),
            rollback_guidance=self._default_rollback_guidance(),
            affected_files=finding.affected_files,
            evidence=evidence_dicts,
            manual_review_required=False,
        )


class FortinetHTTPRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-HTTP-001"
    vendor = "Fortinet"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        interface_name = "port1"
        allowed = ["ping", "ssh", "https"]

        if finding.evidence:
            for ev in finding.evidence:
                if "allowaccess" in ev.source_text.lower():
                    parts = ev.source_text.strip().split()
                    existing_services = [p for p in parts if p.lower() not in ["set", "allowaccess", "http"]]
                    if existing_services:
                        allowed = existing_services

        allowed_str = " ".join(allowed)
        cmds = [
            "config system interface",
            f"edit {interface_name}",
            f"set allowaccess {allowed_str}",
            "next",
            "end",
        ]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Firewall / Security Appliance",
            title="Remove Plaintext HTTP from Interface Allowaccess",
            description="Update FortiOS interface management access list to remove HTTP while preserving HTTPS and SSH.",
            status=RemediationStatusEnum.AVAILABLE,
            review_status=ReviewStatusEnum.PENDING_REVIEW,
            proposed_commands=cmds,
            current_configuration=finding.observed,
            proposed_configuration="\n".join(cmds),
            validation_steps=self._default_validation_steps(self.control_id),
            rollback_guidance=self._default_rollback_guidance(),
            affected_files=finding.affected_files,
            evidence=evidence_dicts,
            manual_review_required=False,
        )


class FortinetManualReviewRemediation(BaseRemediationTemplate):
    """Fallback template for Fortinet controls requiring operator inputs."""

    def __init__(self, control_id: str, title: str, required_inputs: List[str]):
        self.control_id = control_id
        self.vendor = "Fortinet"
        self.title = title
        self.required_inputs = required_inputs

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Firewall / Security Appliance",
            title=self.title,
            description="Automatic remediation is not safe for this control. Operator input is required before generating commands.",
            status=RemediationStatusEnum.MANUAL_REVIEW_REQUIRED,
            review_status=ReviewStatusEnum.PENDING_REVIEW,
            proposed_commands=[],
            current_configuration=finding.observed,
            proposed_configuration="",
            validation_steps=self._default_validation_steps(self.control_id),
            rollback_guidance=self._default_rollback_guidance(),
            affected_files=finding.affected_files,
            evidence=evidence_dicts,
            manual_review_required=True,
            required_inputs=self.required_inputs,
        )
