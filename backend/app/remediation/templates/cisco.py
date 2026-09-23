"""
N-CASA Cisco IOS/NX-OS Remediation Templates
================================================
Deterministic remediation proposals for Cisco IOS/NX-OS configurations.
"""

from typing import List
from app.findings.models import FindingRecord
from app.remediation.models import RemediationRecord, RemediationStatusEnum, ReviewStatusEnum
from app.remediation.templates.base import BaseRemediationTemplate


class CiscoTelnetRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-TELNET-001"
    vendor = "Cisco"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        vty_line = "line vty 0 4"
        if finding.evidence:
            for ev in finding.evidence:
                if "vty" in ev.source_text.lower():
                    vty_line = ev.source_text.strip()
                    break

        cmds = [vty_line, " transport input ssh"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Switch",
            title="Disable Telnet Service on VTY Lines",
            description="Remove Telnet transport from virtual terminal lines and mandate SSH only.",
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


class CiscoSSHRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-SSH-001"
    vendor = "Cisco"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["ip ssh version 2"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Switch",
            title="Enforce SSH Version 2 Protocol",
            description="Explicitly enable SSH version 2 and restrict vulnerable SSH v1 protocols.",
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


class CiscoHTTPRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-HTTP-001"
    vendor = "Cisco"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["no ip http server"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Switch",
            title="Disable Plaintext HTTP Web Server",
            description="Turn off plaintext HTTP daemon while preserving HTTPS web administration.",
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


class CiscoHTTPSRemediation(BaseRemediationTemplate):
    control_id = "CIS-NET-HTTPS-001"
    vendor = "Cisco"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["ip http secure-server"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Switch",
            title="Enable HTTPS Secure Web Management",
            description="Configure HTTPS secure server for encrypted web-based management.",
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


class CiscoAAARemediation(BaseRemediationTemplate):
    control_id = "NIST-NET-AUTH-001"
    vendor = "Cisco"

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        cmds = ["aaa new-model"]
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=self.vendor,
            device_type="Router / Switch",
            title="Enable AAA Authentication Architecture",
            description="Enable AAA model. Note: TACACS+/RADIUS server groups require operator approval.",
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


class CiscoManualReviewRemediation(BaseRemediationTemplate):
    """Fallback template for Cisco controls requiring operator inputs (IPs, Hostnames, Secrets)."""

    def __init__(self, control_id: str, title: str, required_inputs: List[str]):
        self.control_id = control_id
        self.vendor = "Cisco"
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
            device_type="Router / Switch",
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
