"""
Cisco IOS / IOS-XE / NX-OS Configuration Normalizer
====================================================
Transforms Cisco parsed configuration data into vendor-neutral security model.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.normalization.models import (
    NormalizationStatusEnum,
    NormalizedACL,
    NormalizedACLRule,
    NormalizedAuthentication,
    NormalizedConfiguration,
    NormalizedEvidenceItem,
    NormalizedIdentity,
    NormalizedInterface,
    NormalizedInterfaceSwitching,
    NormalizedLogging,
    NormalizedManagement,
    NormalizedNTP,
    NormalizedRouting,
    NormalizedSSH,
    NormalizedTelnet,
    NormalizedVLAN,
)
from app.normalization.normalizer import BaseNormalizer, format_ip_cidr
from app.parsers.base import ParsedConfiguration


class CiscoNormalizer(BaseNormalizer):
    """Transforms Cisco parsed structures into vendor-neutral security models."""

    def normalize(self, parsed_config: ParsedConfiguration) -> NormalizedConfiguration:
        data = parsed_config.data or {}
        file_id = parsed_config.file_id
        vendor = parsed_config.vendor or "Cisco"
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
        ssh_ver = mgmt_raw.get("ssh_version")
        vty_lines = mgmt_raw.get("line_vty", [])

        ssh_enabled = bool(ssh_ver) or any(
            vty.get("transport_input") and "ssh" in vty.get("transport_input", "").lower()
            for vty in vty_lines
        )
        telnet_disabled = any(
            vty.get("transport_input") == "ssh" for vty in vty_lines
        )

        management = NormalizedManagement(
            ssh=NormalizedSSH(
                enabled=True if ssh_enabled else (False if ssh_ver == "disabled" else None),
                version=ssh_ver,
            ),
            telnet=NormalizedTelnet(enabled=False if telnet_disabled else None),
        )

        # 3. Authentication
        auth_raw = data.get("authentication", {})
        authentication = NormalizedAuthentication(
            aaa_enabled=auth_raw.get("aaa_new_model"),
            local_users=auth_raw.get("usernames", []),
            enable_secret_present=auth_raw.get("enable_secret"),
        )

        # 4. Interfaces
        interfaces: List[NormalizedInterface] = []
        for iface in data.get("interfaces", []):
            ip_cidrs: List[str] = []
            for ip_obj in iface.get("ip_addresses", []):
                ip_str = ip_obj.get("ip")
                mask_str = ip_obj.get("netmask")
                if ip_str:
                    ip_cidrs.append(format_ip_cidr(ip_str, mask_str))

            sw_raw = iface.get("switchport", {})
            switching = NormalizedInterfaceSwitching(
                mode=sw_raw.get("mode"),
                access_vlan=sw_raw.get("access_vlan"),
                native_vlan=sw_raw.get("native_vlan"),
                allowed_vlans=sw_raw.get("allowed_vlans", []),
            ) if sw_raw else None

            # Cisco shutdown rule: shutdown=True -> enabled=False; shutdown=False -> enabled=True
            is_enabled = not iface.get("shutdown", False)

            interfaces.append(
                NormalizedInterface(
                    name=iface.get("name", "unknown"),
                    description=iface.get("description"),
                    enabled=is_enabled,
                    ip_addresses=ip_cidrs,
                    switching=switching,
                )
            )

        # 5. Routing
        routing_raw = data.get("routing", {})
        routing = NormalizedRouting(
            static_routes=routing_raw.get("static_routes", []),
            ospf_configured=routing_raw.get("ospf") is not None,
            bgp_configured=routing_raw.get("bgp") is not None,
            eigrp_configured=routing_raw.get("eigrp") is not None,
        )

        # 6. VLANs
        vlans = [
            NormalizedVLAN(id=v["vlan_id"], name=v.get("name"))
            for v in data.get("vlans", [])
        ]

        # 7. ACLs
        acls: List[NormalizedACL] = []
        for acl in data.get("acls", []):
            rules = []
            if "rule" in acl:
                rules.append(NormalizedACLRule(action=acl["rule"].split()[0]))
            elif "rules" in acl:
                for r in acl["rules"]:
                    rules.append(NormalizedACLRule(action=str(r)))
            acls.append(NormalizedACL(name=acl["name"], type=acl.get("type"), rules=rules))

        # 8. Logging
        log_raw = data.get("logging", {})
        logging_obj = NormalizedLogging(
            enabled=bool(log_raw.get("hosts") or log_raw.get("buffered")),
            remote_servers=log_raw.get("hosts", []),
            local_logging=bool(log_raw.get("buffered")),
        )

        # 9. NTP
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
            normalizer="CiscoNormalizer",
            identity=identity,
            management=management,
            authentication=authentication,
            interfaces=interfaces,
            routing=routing,
            vlans=vlans,
            acls=acls,
            logging=logging_obj,
            ntp=ntp_obj,
            evidence=norm_evidence,
        )
