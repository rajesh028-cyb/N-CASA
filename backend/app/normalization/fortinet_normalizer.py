"""
Fortinet FortiOS Configuration Normalizer
===========================================
Transforms FortiOS parsed configuration data into vendor-neutral security model.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.normalization.models import (
    NormalizationStatusEnum,
    NormalizedACL,
    NormalizedConfiguration,
    NormalizedEvidenceItem,
    NormalizedFirewallPolicy,
    NormalizedHTTP,
    NormalizedHTTPS,
    NormalizedIdentity,
    NormalizedInterface,
    NormalizedLogging,
    NormalizedManagement,
    NormalizedNTP,
    NormalizedRouting,
    NormalizedSSH,
    NormalizedVPN,
)
from app.normalization.normalizer import BaseNormalizer, format_ip_cidr
from app.parsers.base import ParsedConfiguration


class FortinetNormalizer(BaseNormalizer):
    """Transforms Fortinet FortiOS parsed structures into vendor-neutral security models."""

    def normalize(self, parsed_config: ParsedConfiguration) -> NormalizedConfiguration:
        data = parsed_config.data or {}
        file_id = parsed_config.file_id
        vendor = parsed_config.vendor or "Fortinet"
        device_type = parsed_config.device_type or "Firewall"

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

        # 2. Management (derived from interface allowaccess settings)
        interfaces_raw = data.get("interfaces", [])
        ssh_allowed = False
        https_allowed = False
        http_allowed = False

        interfaces: List[NormalizedInterface] = []
        for iface in interfaces_raw:
            allow_access = [a.lower() for a in iface.get("allowaccess", [])]
            if "ssh" in allow_access:
                ssh_allowed = True
            if "https" in allow_access:
                https_allowed = True
            if "http" in allow_access:
                http_allowed = True

            ip_str = iface.get("ip")
            ip_cidrs = [format_ip_cidr(ip_str)] if ip_str else []

            interfaces.append(
                NormalizedInterface(
                    name=iface.get("name", "port1"),
                    description=iface.get("description"),
                    enabled=iface.get("status") != "down",
                    ip_addresses=ip_cidrs,
                )
            )

        management = NormalizedManagement(
            ssh=NormalizedSSH(enabled=True if ssh_allowed else None),
            https=NormalizedHTTPS(enabled=True if https_allowed else None),
            http=NormalizedHTTP(enabled=True if http_allowed else None),
        )

        # 3. Firewall Policies
        fw_policies: List[NormalizedFirewallPolicy] = []
        for pol in data.get("firewall_policies", []):
            fw_policies.append(
                NormalizedFirewallPolicy(
                    id=str(pol.get("policy_id", "1")),
                    name=pol.get("name"),
                    source_interfaces=[pol.get("srcintf")] if pol.get("srcintf") else [],
                    destination_interfaces=[pol.get("dstintf")] if pol.get("dstintf") else [],
                    source_addresses=[pol.get("srcaddr")] if pol.get("srcaddr") else [],
                    destination_addresses=[pol.get("dstaddr")] if pol.get("dstaddr") else [],
                    services=[pol.get("service")] if pol.get("service") else [],
                    action=str(pol.get("action", "accept")).upper(),
                    schedule=pol.get("schedule"),
                )
            )

        # 4. Routing (static routes)
        static_routes = []
        for r in data.get("static_routes", []):
            static_routes.append({
                "destination": format_ip_cidr(r.get("dst")),
                "gateway": r.get("gateway"),
                "device": r.get("device"),
            })
        routing = NormalizedRouting(static_routes=static_routes)

        # 5. Logging
        log_raw = data.get("logging", {})
        logging_obj = NormalizedLogging(
            enabled=log_raw.get("configured", False),
            remote_servers=log_raw.get("targets", []),
        )

        # 6. NTP
        ntp_raw = data.get("ntp", {})
        ntp_servers = ntp_raw.get("servers", [])
        ntp_obj = NormalizedNTP(
            enabled=len(ntp_servers) > 0,
            servers=ntp_servers,
        )

        # 7. VPN
        vpn_raw = data.get("vpn", {})
        vpn_obj = NormalizedVPN(
            configured=vpn_raw.get("configured", False),
            types=vpn_raw.get("sections", []),
        )

        return NormalizedConfiguration(
            file_id=file_id,
            vendor=vendor,
            device_type=device_type,
            status=NormalizationStatusEnum.NORMALIZED,
            normalizer="FortinetNormalizer",
            identity=identity,
            management=management,
            interfaces=interfaces,
            firewall_policies=fw_policies,
            routing=routing,
            logging=logging_obj,
            ntp=ntp_obj,
            vpn=vpn_obj,
            evidence=norm_evidence,
        )
