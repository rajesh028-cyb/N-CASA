"""
N-CASA Juniper Junos Remediation Templates
=============================================
Deterministic remediation proposals for Juniper Junos set-style & hierarchical configurations.
"""

from typing import List
from app.findings.models import FindingRecord
from app.remediation.models import RemediationRecord, RemediationStatusEnum, ReviewStatusEnum
from app.remediation.templates.base import BaseRemediationTemplate


class JuniperTelnetRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-TELNET-001"
    vendor = "Juniper"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["delete system services telnet", "set system services ssh"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Security Gateway",
            title="Disable Junos Telnet Service",
            description="Remove Telnet service from system configuration and mandate SSH service.",
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


class JuniperHTTPRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-HTTP-001"
    vendor = "Juniper"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["delete system services web-management http"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Security Gateway",
            title="Disable Plaintext Junos Web Management HTTP",
            description="Delete plaintext HTTP web-management while preserving HTTPS web management.",
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


class JuniperHTTPSRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-HTTPS-001"
    vendor = "Juniper"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["set system services web-management https"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Security Gateway",
            title="Enable Junos HTTPS Web Management",
            description="Configure HTTPS web management for secure web access.",
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


class JuniperSSHRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-SSH-001"
    vendor = "Juniper"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["set system services ssh"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Security Gateway",
            title="Enable Junos SSH Service",
            description="Enable SSH management service in Junos system settings.",
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


class JuniperManualReviewRemediation(BaseRemediationTemplate):
    """Fallback template for Junos controls requiring operator inputs."""

    def __init__(self, control_id: str, title: str, required_inputs: List[str]):
        self.control_id = control_id
        self.vendor = "Juniper"
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
            device_type="Router / Security Gateway",
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
