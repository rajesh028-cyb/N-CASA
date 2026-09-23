"""
NIST Framework Compliance Rules
=================================
Deterministic rules for NIST SP 800-53 controls.
Operates exclusively on NormalizedConfiguration fields.
"""

from typing import List
from app.compliance.catalog import get_catalog_control_by_id
from app.compliance.models import (
    ComplianceEvidence,
    ComplianceResult,
    ComplianceStatusEnum,
)
from app.compliance.rules.base import BaseComplianceRule
from app.normalization.models import NormalizedConfiguration


class NIST_AAA_Rule(BaseComplianceRule):
    """NIST-NET-AUTH-001: Centralized Authentication and AAA Framework."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("NIST-NET-AUTH-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        auth = config.authentication
        ev = self.filter_evidence(config, "authentication")

        if auth.aaa_enabled is True or auth.enable_secret_present is True:
            status = ComplianceStatusEnum.PASS
            obs = f"AAA authentication is configured (aaa_enabled: {auth.aaa_enabled}, enable_secret_present: {auth.enable_secret_present})"
            exp = "Centralized authentication (AAA) or secure encrypted administrative secrets must be configured."
            explanation = "AAA authentication framework or encrypted administrative secret is active."
        elif auth.aaa_enabled is False and auth.enable_secret_present is False:
            status = ComplianceStatusEnum.FAIL
            obs = "AAA framework is explicitly disabled and no encrypted enable secret is present"
            exp = "Centralized authentication (AAA) or secure encrypted administrative secrets must be configured."
            explanation = "Administrative access lacks AAA authentication controls or encrypted secret protection."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "AAA configuration state is unverified"
            exp = "Centralized authentication (AAA) or secure encrypted administrative secrets must be configured."
            explanation = "Normalized configuration contains insufficient AAA status evidence."

        return ComplianceResult(
            control_id=self.control_id,
            framework=self.framework,
            title=self.title,
            description=self.metadata.description,
            severity=self.severity,
            category=self.category,
            status=status,
            expected=exp,
            observed=obs,
            explanation=explanation,
            evidence=ev,
            rule=self.rule_name,
            internal_mapping=True,
        )


class NIST_Logging_Rule(BaseComplianceRule):
    """NIST-NET-LOG-001: Centralized Syslog Event Audit Logging."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("NIST-NET-LOG-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        logging_obj = config.logging
        ev = self.filter_evidence(config, "logging")

        if logging_obj.remote_servers and len(logging_obj.remote_servers) > 0:
            status = ComplianceStatusEnum.PASS
            obs = f"Remote logging configured with {len(logging_obj.remote_servers)} host(s): {', '.join(logging_obj.remote_servers)}"
            exp = "Device audit event logging must be forwarded to centralized remote Syslog servers."
            explanation = "Remote Syslog server targets are configured for central security logging."
        elif logging_obj.enabled is False:
            status = ComplianceStatusEnum.FAIL
            obs = "Audit event logging is explicitly disabled"
            exp = "Device audit event logging must be forwarded to centralized remote Syslog servers."
            explanation = "Logging subsystem is explicitly disabled."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "No remote Syslog servers configured in parsed scope"
            exp = "Device audit event logging must be forwarded to centralized remote Syslog servers."
            explanation = "Remote logging server definitions were not identified in configuration evidence."

        return ComplianceResult(
            control_id=self.control_id,
            framework=self.framework,
            title=self.title,
            description=self.metadata.description,
            severity=self.severity,
            category=self.category,
            status=status,
            expected=exp,
            observed=obs,
            explanation=explanation,
            evidence=ev,
            rule=self.rule_name,
            internal_mapping=True,
        )


class NIST_NTP_Rule(BaseComplianceRule):
    """NIST-NET-NTP-001: Network Time Protocol Synchronization."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("NIST-NET-NTP-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        ntp = config.ntp
        ev = self.filter_evidence(config, "ntp")

        if ntp.servers and len(ntp.servers) > 0:
            status = ComplianceStatusEnum.PASS
            obs = f"NTP time synchronization configured with {len(ntp.servers)} server(s): {', '.join(ntp.servers)}"
            exp = "Device clock must synchronize time with reliable NTP time servers."
            explanation = "NTP server entries are configured for accurate event timestamping."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "No NTP servers configured in parsed scope"
            exp = "Device clock must synchronize time with reliable NTP time servers."
            explanation = "NTP server configuration was not identified in normalized data."

        return ComplianceResult(
            control_id=self.control_id,
            framework=self.framework,
            title=self.title,
            description=self.metadata.description,
            severity=self.severity,
            category=self.category,
            status=status,
            expected=exp,
            observed=obs,
            explanation=explanation,
            evidence=ev,
            rule=self.rule_name,
            internal_mapping=True,
        )


class NIST_VPN_Rule(BaseComplianceRule):
    """NIST-NET-VPN-001: Virtual Private Network Configuration Visibility."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("NIST-NET-VPN-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        vpn = config.vpn
        ev = self.filter_evidence(config, "vpn")

        if vpn.configured is True and (len(vpn.tunnels) > 0 or len(vpn.types) > 0):
            status = ComplianceStatusEnum.PASS
            obs = f"VPN configuration detected (types: {', '.join(vpn.types) or 'IPsec/SSL'}, tunnels: {len(vpn.tunnels)})"
            exp = "VPN configuration should be parsed with usable structure for security audit."
            explanation = "Structured VPN configuration parameters parsed successfully."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "No structured VPN configuration detected"
            exp = "VPN configuration should be parsed with usable structure for security audit."
            explanation = "Configuration contains no verifiable VPN tunnel or service definitions."

        return ComplianceResult(
            control_id=self.control_id,
            framework=self.framework,
            title=self.title,
            description=self.metadata.description,
            severity=self.severity,
            category=self.category,
            status=status,
            expected=exp,
            observed=obs,
            explanation=explanation,
            evidence=ev,
            rule=self.rule_name,
            internal_mapping=True,
        )
