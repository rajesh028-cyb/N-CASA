"""
N-CASA Remediation Template Registry
======================================
Registry mapping vendor and control ID pairs to deterministic remediation templates.
Unknown vendors or underspecified controls return a safe MANUAL_REVIEW_REQUIRED fallback template.
"""

from typing import Dict, Tuple
from app.findings.models import FindingRecord
from app.remediation.models import RemediationRecord, RemediationStatusEnum, ReviewStatusEnum
from app.remediation.templates import (
    BaseRemediationTemplate,
    CiscoAAARemediation,
    CiscoHTTPRemediation,
    CiscoHTTPSRemediation,
    CiscoManualReviewRemediation,
    CiscoSSHRemediation,
    CiscoTelnetRemediation,
    FortinetHTTPRemediation,
    FortinetManualReviewRemediation,
    FortinetTelnetRemediation,
    JuniperHTTPRemediation,
    JuniperHTTPSRemediation,
    JuniperManualReviewRemediation,
    JuniperSSHRemediation,
    JuniperTelnetRemediation,
)


class FallbackManualReviewTemplate(BaseRemediationTemplate):
    """Fallback template returned when no deterministic template exists or for unknown vendors."""

    def __init__(self, vendor: str, control_id: str, reason: str, required_inputs: list[str] = None):
        self.vendor = vendor
        self.control_id = control_id
        self.reason = reason
        self.required_inputs = required_inputs or ["Operator review and manual configuration"]

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        rem_id = f"REM-{finding.audit_id}-{finding.finding_id}"
        evidence_dicts = [ev.model_dump() for ev in finding.evidence]

        return RemediationRecord(
            remediation_id=rem_id,
            finding_id=finding.finding_id,
            audit_id=finding.audit_id,
            control_id=self.control_id,
            framework=finding.framework,
            vendor=finding.vendor if (finding.vendor and finding.vendor != "UNKNOWN") else self.vendor,
            device_type="Network Device",
            title=f"Manual Review Required for {finding.title}",
            description=f"Automatic remediation is not available: {self.reason}",
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


class RemediationTemplateRegistry:
    """Registry mapping (vendor, control_id) to template instances."""

    def __init__(self):
        self._registry: Dict[Tuple[str, str], BaseRemediationTemplate] = {}
        self._register_default_templates()

    def register(self, vendor: str, control_id: str, template: BaseRemediationTemplate):
        key = (vendor.strip().upper(), control_id.strip().upper())
        self._registry[key] = template

    def get_template(self, vendor: str, control_id: str) -> BaseRemediationTemplate:
        v_upper = vendor.strip().upper() if vendor else "UNKNOWN"
        c_upper = control_id.strip().upper() if control_id else ""

        if v_upper == "UNKNOWN":
            return FallbackManualReviewTemplate(
                vendor="UNKNOWN",
                control_id=control_id,
                reason="Vendor is unknown or unsupported for automatic remediation.",
                required_inputs=["Vendor detection confirmation", "Approved device syntax"],
            )

        key = (v_upper, c_upper)
        if key in self._registry:
            return self._registry[key]

        # Specific underspecified controls fallbacks with helpful required inputs
        required_inputs_map = {
            "CIS-NET-HOST-001": ["Approved device hostname"],
            "NIST-NET-LOG-001": ["Syslog server IP address", "Facility & severity levels"],
            "NIST-NET-NTP-001": ["Approved NTP server IP address"],
            "NIST-NET-VPN-001": ["IPsec/SSL VPN peer address", "Preshared key / Certificate"],
            "STIG-NET-ROUTING-001": ["Routing protocol authentication key ID", "Password/Key string"],
            "CIS-NET-FW-001": ["Firewall policy default action intent"],
            "CIS-NET-ACL-001": ["ACL rule action intent (permit/deny)"],
        }
        req_inputs = required_inputs_map.get(
            c_upper, ["Operator review and manual syntax validation"]
        )

        return FallbackManualReviewTemplate(
            vendor=vendor,
            control_id=control_id,
            reason=f"Control {control_id} requires operator input or safe manual review.",
            required_inputs=req_inputs,
        )

    def _register_default_templates(self):
        # Cisco templates
        self.register("CISCO", "CIS-NET-TELNET-001", CiscoTelnetRemediation())
        self.register("CISCO", "CIS-NET-SSH-001", CiscoSSHRemediation())
        self.register("CISCO", "CIS-NET-HTTP-001", CiscoHTTPRemediation())
        self.register("CISCO", "CIS-NET-HTTPS-001", CiscoHTTPSRemediation())
        self.register("CISCO", "NIST-NET-AUTH-001", CiscoAAARemediation())

        # Juniper templates
        self.register("JUNIPER", "CIS-NET-TELNET-001", JuniperTelnetRemediation())
        self.register("JUNIPER", "CIS-NET-SSH-001", JuniperSSHRemediation())
        self.register("JUNIPER", "CIS-NET-HTTP-001", JuniperHTTPRemediation())
        self.register("JUNIPER", "CIS-NET-HTTPS-001", JuniperHTTPSRemediation())

        # Fortinet templates
        self.register("FORTINET", "CIS-NET-TELNET-001", FortinetTelnetRemediation())
        self.register("FORTINET", "CIS-NET-HTTP-001", FortinetHTTPRemediation())


# Global singleton registry instance
remediation_registry = RemediationTemplateRegistry()
