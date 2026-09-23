"""
CIS Framework Compliance Rules
================================
Deterministic rules for CIS Benchmarks controls.
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


class CIS_SSH_Rule(BaseComplianceRule):
    """CIS-NET-SSH-001: Secure SSH Management Configuration."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-SSH-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        ssh = config.management.ssh
        ev = self.filter_evidence(config, "management.ssh")

        if ssh.enabled is True and (ssh.version == "2" or ssh.version is None):
            # SSH enabled and version 2 (or modern default where version is unversioned)
            status = ComplianceStatusEnum.PASS
            obs = f"SSH is explicitly enabled (version: {ssh.version or '2'})"
            exp = "SSH version 2 must be explicitly enabled for management access."
            explanation = "SSH management protocol is securely enabled with version 2."
        elif ssh.enabled is True and ssh.version == "1":
            status = ComplianceStatusEnum.FAIL
            obs = "SSH version 1 is enabled"
            exp = "SSH version 2 must be explicitly enabled for management access."
            explanation = "Insecure SSH protocol version 1 detected."
        elif ssh.enabled is False:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "SSH management is explicitly disabled"
            exp = "SSH version 2 must be explicitly enabled for management access."
            explanation = "SSH is disabled; secure remote management availability cannot be verified."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "No SSH configuration status present"
            exp = "SSH version 2 must be explicitly enabled for management access."
            explanation = "Normalized configuration contains no verifiable SSH management state."

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


class CIS_Telnet_Rule(BaseComplianceRule):
    """CIS-NET-TELNET-001: Disable Insecure Telnet Management."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-TELNET-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        telnet = config.management.telnet
        ev = self.filter_evidence(config, "management.telnet")

        if telnet.enabled is True:
            status = ComplianceStatusEnum.FAIL
            obs = "Telnet management service is explicitly enabled"
            exp = "Insecure cleartext Telnet management protocol must be explicitly disabled."
            explanation = "Cleartext Telnet management protocol exposes credentials to eavesdropping."
        elif telnet.enabled is False:
            status = ComplianceStatusEnum.PASS
            obs = "Telnet management service is explicitly disabled"
            exp = "Insecure cleartext Telnet management protocol must be explicitly disabled."
            explanation = "Unencrypted Telnet management service is properly disabled."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "Telnet management state is not specified"
            exp = "Insecure cleartext Telnet management protocol must be explicitly disabled."
            explanation = "Normalized configuration contains no explicit Telnet status evidence."

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


class CIS_HTTP_Rule(BaseComplianceRule):
    """CIS-NET-HTTP-001: Disable Unencrypted HTTP Management Server."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-HTTP-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        http = config.management.http
        ev = self.filter_evidence(config, "management.http")

        if http.enabled is True:
            status = ComplianceStatusEnum.FAIL
            obs = "Unencrypted HTTP web management server is explicitly enabled"
            exp = "Unencrypted HTTP web management service must be explicitly disabled."
            explanation = "Cleartext HTTP server exposes management sessions to credential interception."
        elif http.enabled is False:
            status = ComplianceStatusEnum.PASS
            obs = "Unencrypted HTTP web management server is explicitly disabled"
            exp = "Unencrypted HTTP web management service must be explicitly disabled."
            explanation = "Unencrypted HTTP web management server is properly disabled."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "HTTP management server state is not specified"
            exp = "Unencrypted HTTP web management service must be explicitly disabled."
            explanation = "Normalized configuration contains no explicit HTTP server status evidence."

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


class CIS_HTTPS_Rule(BaseComplianceRule):
    """CIS-NET-HTTPS-001: Enable Encrypted HTTPS Web Management."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-HTTPS-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        https = config.management.https
        ev = self.filter_evidence(config, "management.https")

        if https.enabled is True:
            status = ComplianceStatusEnum.PASS
            obs = "Encrypted HTTPS web management server is explicitly enabled"
            exp = "Secure HTTPS web management service should be enabled when web management is required."
            explanation = "Encrypted HTTPS management server is active."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "HTTPS web management server state is not specified / disabled"
            exp = "Secure HTTPS web management service should be enabled when web management is required."
            explanation = "HTTPS status cannot be verified from available configuration evidence."

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


class CIS_Hostname_Rule(BaseComplianceRule):
    """CIS-NET-ID-001: Device Hostname and Identification."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-ID-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        hostname = config.identity.hostname
        ev = self.filter_evidence(config, "hostname")

        if hostname and hostname.strip() and hostname.lower() not in ["router", "switch", "default", "localhost"]:
            status = ComplianceStatusEnum.PASS
            obs = f"Device hostname is defined as '{hostname}'"
            exp = "Device hostname must be explicitly configured with a non-default identifier."
            explanation = f"Unique host identification '{hostname}' is assigned to the device."
        elif hostname and hostname.lower() in ["router", "switch", "default", "localhost"]:
            status = ComplianceStatusEnum.FAIL
            obs = f"Device hostname is set to default string '{hostname}'"
            exp = "Device hostname must be explicitly configured with a non-default identifier."
            explanation = "Default generic hostname makes audit identification and logging ineffective."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "Device hostname is not specified"
            exp = "Device hostname must be explicitly configured with a non-default identifier."
            explanation = "Hostname configuration line was not identified in normalized data."

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


class CIS_InterfaceState_Rule(BaseComplianceRule):
    """CIS-NET-IFACE-001: Administrative Shutdown of Unused Interfaces."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-IFACE-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        ifaces = config.interfaces
        ev = self.filter_evidence(config, "interfaces")

        if not ifaces:
            return ComplianceResult(
                control_id=self.control_id,
                framework=self.framework,
                title=self.title,
                description=self.metadata.description,
                severity=self.severity,
                category=self.category,
                status=ComplianceStatusEnum.NOT_VERIFIABLE,
                expected="Unused interfaces should be administratively disabled.",
                observed="No interfaces identified in normalized configuration.",
                explanation="Configuration contains no verifiable interface definitions.",
                evidence=[],
                rule=self.rule_name,
                internal_mapping=True,
            )

        disabled_ifaces = [i.name for i in ifaces if i.enabled is False]
        if disabled_ifaces:
            status = ComplianceStatusEnum.PASS
            obs = f"{len(disabled_ifaces)} interface(s) explicitly disabled: {', '.join(disabled_ifaces)}"
            exp = "Unused interfaces should be administratively disabled."
            explanation = "Found administrative shutdown configuration on unused interfaces."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = f"All {len(ifaces)} interface(s) are active/enabled or unverified"
            exp = "Unused interfaces should be administratively disabled."
            explanation = "Cannot verify whether enabled interfaces are in active use or should be disabled."

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


class CIS_FirewallPolicy_Rule(BaseComplianceRule):
    """CIS-NET-FW-001: Firewall Policy Action Explicitness."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-FW-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        policies = config.firewall_policies
        ev = self.filter_evidence(config, "firewall")

        if not policies:
            return ComplianceResult(
                control_id=self.control_id,
                framework=self.framework,
                title=self.title,
                description=self.metadata.description,
                severity=self.severity,
                category=self.category,
                status=ComplianceStatusEnum.NOT_VERIFIABLE,
                expected="All firewall policies must specify explicit ACCEPT or DENY actions.",
                observed="No firewall security policies configured on device.",
                explanation="Device configuration contains no firewall security policies to evaluate.",
                evidence=[],
                rule=self.rule_name,
                internal_mapping=True,
            )

        missing_action = [p.name for p in policies if not p.action]
        if missing_action:
            status = ComplianceStatusEnum.FAIL
            obs = f"Policy '{missing_action[0]}' lacks an explicit action"
            exp = "All firewall policies must specify explicit ACCEPT or DENY actions."
            explanation = "Ambiguous firewall policy without explicit action found."
        else:
            status = ComplianceStatusEnum.PASS
            obs = f"All {len(policies)} firewall policy/policies specify explicit actions"
            exp = "All firewall policies must specify explicit ACCEPT or DENY actions."
            explanation = "Every configured firewall security policy contains an explicit action."

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


class CIS_ACL_Rule(BaseComplianceRule):
    """CIS-NET-ACL-001: ACL Rule Action Explicitness."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("CIS-NET-ACL-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        acls = config.acls
        ev = self.filter_evidence(config, "acls")

        if not acls:
            return ComplianceResult(
                control_id=self.control_id,
                framework=self.framework,
                title=self.title,
                description=self.metadata.description,
                severity=self.severity,
                category=self.category,
                status=ComplianceStatusEnum.NOT_VERIFIABLE,
                expected="All ACL entries must specify explicit permit or deny actions.",
                observed="No Access Control Lists (ACLs) configured.",
                explanation="Configuration contains no ACL definitions to evaluate.",
                evidence=[],
                rule=self.rule_name,
                internal_mapping=True,
            )

        missing_action_rules = []
        for acl in acls:
            for rule in acl.rules:
                action = rule.action if hasattr(rule, "action") else (rule.get("action") if isinstance(rule, dict) else None)
                if not action:
                    missing_action_rules.append(acl.name)

        if missing_action_rules:
            status = ComplianceStatusEnum.FAIL
            obs = f"ACL '{missing_action_rules[0]}' contains rule entries without explicit permit/deny action"
            exp = "All ACL entries must specify explicit permit or deny actions."
            explanation = "Ambiguous ACL rule missing explicit action detected."
        else:
            status = ComplianceStatusEnum.PASS
            obs = f"All {len(acls)} Access Control List(s) contain explicit permit/deny actions"
            exp = "All ACL entries must specify explicit permit or deny actions."
            explanation = "Every configured ACL entry explicitly specifies a permit or deny action."

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
