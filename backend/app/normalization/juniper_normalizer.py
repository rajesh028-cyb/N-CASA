"""
Juniper Junos Configuration Normalizer
======================================
Transforms Juniper parsed configuration data into vendor-neutral security model.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.normalization.models import (
    NormalizationStatusEnum,
    NormalizedAuthentication,
    NormalizedConfiguration,
    NormalizedEvidenceItem,
    NormalizedFirewallPolicy,
    NormalizedIdentity,
    NormalizedInterface,
    NormalizedLogging,
    NormalizedManagement,
    NormalizedNTP,
    NormalizedRouting,
    NormalizedSSH,
    NormalizedSecurityZone,
)
from app.normalization.normalizer import BaseNormalizer, format_ip_cidr
from app.parsers.base import ParsedConfiguration


class JuniperNormalizer(BaseNormalizer):
    """Transforms Juniper Junos parsed structures into vendor-neutral security models."""

    def normalize(self, parsed_config: ParsedConfiguration) -> NormalizedConfiguration:
        data = parsed_config.data or {}
        file_id = parsed_config.file_id
        vendor = parsed_config.vendor or "Juniper"
        device_type = parsed_config.device_type or "Unknown"

        norm_evidence: List[NormalizedEvidenceItem] = []

        # Map parser evidence items into NormalizedEvidenceItem
        for p_ev in parsed_config.evidence:
            norm_evidence.append(
                NormalizedEvidenceItem(
                    field=p_ev.field,
                    value=None,
                    source_vendor=vendor,
                    source_file=file_id,
                    source_line=p_ev.line,
                    source_text=p_ev.text,
                    source="normalizer",
                )
            )

        # 1. Identity
        hostname = data.get("hostname")
        identity = NormalizedIdentity(hostname=hostname)

        # 2. Management
        mgmt_raw = data.get("management", {})
        ssh_enabled = mgmt_raw.get("ssh_enabled") or ("ssh" in mgmt_raw.get("services", []))
        management = NormalizedManagement(
            ssh=NormalizedSSH(enabled=True if ssh_enabled else None),
        )

        # 3. Interfaces
        interfaces: List[NormalizedInterface] = []
        for iface in data.get("interfaces", []):
            ip_cidrs = [format_ip_cidr(ip) for ip in iface.get("ip_addresses", [])]
            interfaces.append(
                NormalizedInterface(
                    name=iface.get("name", "ge-0/0/0"),
                    description=iface.get("description"),
                    enabled=iface.get("enabled", True),
                    ip_addresses=ip_cidrs,
                )
            )

        # 4. Security Zones & Security Policies
        sec_raw = data.get("security", {})
        sec_zones: List[NormalizedSecurityZone] = []
        for z in sec_raw.get("zones", []):
            sec_zones.append(
                NormalizedSecurityZone(
                    name=z["name"],
                    interfaces=z.get("interfaces", []),
                )
            )

        sec_policies: List[NormalizedFirewallPolicy] = []
        for p in sec_raw.get("policies", []):
            sec_policies.append(
                NormalizedFirewallPolicy(
                    id=p["name"],
                    name=p["name"],
                    source_interfaces=[p["from_zone"]] if "from_zone" in p else [],
                    destination_interfaces=[p["to_zone"]] if "to_zone" in p else [],
                    action=p.get("action", "permit").upper(),
                )
            )

        # 5. Routing
        routing_raw = data.get("routing", {})
        routing = NormalizedRouting(
            static_routes=routing_raw.get("static_routes", []),
            ospf_configured=routing_raw.get("ospf"),
            bgp_configured=routing_raw.get("bgp"),
        )

        # 6. Syslog / Logging
        sys_raw = data.get("syslog", {})
        sys_hosts = sys_raw.get("hosts", [])
        logging_obj = NormalizedLogging(
            enabled=len(sys_hosts) > 0,
            remote_servers=sys_hosts,
        )

        # 7. NTP
        ntp_raw = data.get("ntp", {})
        ntp_servers = ntp_raw.get("servers", [])
        ntp_obj = NormalizedNTP(
            enabled=len(ntp_servers) > 0,
            servers=ntp_servers,
        )

        return NormalizedConfiguration(
            file_id=file_id,
            vendor=vendor,
            device_type=device_type,
            status=NormalizationStatusEnum.NORMALIZED,
            normalizer="JuniperNormalizer",
            identity=identity,
            management=management,
            interfaces=interfaces,
            security_zones=sec_zones,
            firewall_policies=sec_policies,
            routing=routing,
            logging=logging_obj,
            ntp=ntp_obj,
            evidence=norm_evidence,
        )
