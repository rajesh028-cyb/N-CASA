"""
N-CASA Centralized Compliance Control Catalog
==============================================
Defines the initial 13 security controls across CIS, NIST, and DISA STIG frameworks.
Uses explicit internal mapping identifiers (e.g., CIS-NET-SSH-001) per specification.
"""

from typing import Dict, List
from app.compliance.models import ComplianceSeverityEnum, ControlMetadata

CONTROL_CATALOG: List[ControlMetadata] = [
    # ── CIS Controls ──────────────────────────────────────────────────────────
    ControlMetadata(
        control_id="CIS-NET-SSH-001",
        framework="CIS",
        title="Secure SSH Management Configuration",
        description="Verify that SSH remote management is explicitly enabled and uses secure protocol version 2.",
        severity=ComplianceSeverityEnum.HIGH,
        category="Management Access",
        rule="cis_net_ssh_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-TELNET-001",
        framework="CIS",
        title="Disable Insecure Telnet Management",
        description="Verify that cleartext Telnet management protocol is explicitly disabled or not configured.",
        severity=ComplianceSeverityEnum.HIGH,
        category="Management Access",
        rule="cis_net_telnet_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-HTTP-001",
        framework="CIS",
        title="Disable Unencrypted HTTP Management Server",
        description="Verify that unencrypted HTTP web management server is explicitly disabled.",
        severity=ComplianceSeverityEnum.HIGH,
        category="Management Access",
        rule="cis_net_http_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-HTTPS-001",
        framework="CIS",
        title="Enable Encrypted HTTPS Web Management",
        description="Verify that secure encrypted HTTPS web management service is explicitly enabled.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="Management Access",
        rule="cis_net_https_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-ID-001",
        framework="CIS",
        title="Device Hostname and Identification",
        description="Verify that device identity/hostname is explicitly defined and non-default.",
        severity=ComplianceSeverityEnum.LOW,
        category="Device Identity",
        rule="cis_net_id_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-IFACE-001",
        framework="CIS",
        title="Administrative Shutdown of Unused Interfaces",
        description="Verify that unused or administrative interfaces are explicitly placed in shutdown state.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="Network Interfaces",
        rule="cis_net_iface_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-FW-001",
        framework="CIS",
        title="Firewall Policy Action Explicitness",
        description="Verify that all configured firewall security policies specify explicit ACCEPT/DENY actions.",
        severity=ComplianceSeverityEnum.HIGH,
        category="Firewall & Security Policy",
        rule="cis_net_fw_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="CIS-NET-ACL-001",
        framework="CIS",
        title="ACL Rule Action Explicitness",
        description="Verify that all configured Access Control List (ACL) rules specify explicit permit/deny actions.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="Access Control Lists",
        rule="cis_net_acl_001",
        internal_mapping=True,
    ),

    # ── NIST Controls ─────────────────────────────────────────────────────────
    ControlMetadata(
        control_id="NIST-NET-AUTH-001",
        framework="NIST",
        title="Centralized Authentication and AAA Framework",
        description="Verify that AAA authentication framework and privileged secrets are configured.",
        severity=ComplianceSeverityEnum.HIGH,
        category="AAA & Credentials",
        rule="nist_net_auth_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="NIST-NET-LOG-001",
        framework="NIST",
        title="Centralized Syslog Event Audit Logging",
        description="Verify that remote syslog servers are configured for audit event logging.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="Logging & Audit",
        rule="nist_net_log_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="NIST-NET-NTP-001",
        framework="NIST",
        title="Network Time Protocol Synchronization",
        description="Verify that time synchronization with authoritative NTP servers is configured.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="System Management",
        rule="nist_net_ntp_001",
        internal_mapping=True,
    ),
    ControlMetadata(
        control_id="NIST-NET-VPN-001",
        framework="NIST",
        title="Virtual Private Network Configuration Visibility",
        description="Verify that IPsec/SSL VPN configurations are parsed with sufficient visibility for audit.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="VPN & Encryption",
        rule="nist_net_vpn_001",
        internal_mapping=True,
    ),

    # ── STIG Controls ─────────────────────────────────────────────────────────
    ControlMetadata(
        control_id="STIG-NET-ROUTING-001",
        framework="STIG",
        title="Dynamic Routing Protocol Configuration Visibility",
        description="Verify that dynamic routing configurations (OSPF/BGP/Static) are explicitly defined and visible.",
        severity=ComplianceSeverityEnum.MEDIUM,
        category="Routing & Protocols",
        rule="stig_net_routing_001",
        internal_mapping=True,
    ),
]


def get_catalog_controls(framework: str = None) -> List[ControlMetadata]:
    """Retrieve catalog controls, optionally filtered by framework (case-insensitive)."""
    if not framework:
        return list(CONTROL_CATALOG)
    fw_upper = framework.strip().upper()
    return [c for c in CONTROL_CATALOG if c.framework.upper() == fw_upper]


def get_catalog_control_by_id(control_id: str) -> ControlMetadata | None:
    """Retrieve metadata for a specific control ID."""
    c_id_upper = control_id.strip().upper()
    for c in CONTROL_CATALOG:
        if c.control_id.upper() == c_id_upper:
            return c
    return None
