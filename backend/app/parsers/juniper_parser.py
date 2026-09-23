"""
Juniper Junos Configuration Parser
===================================
Converts Junos configuration text (supporting both set-style and hierarchical {})
into structured vendor data with source line numbers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.parsers.base import (
    BaseParser,
    ParsedConfiguration,
    ParsedEvidenceItem,
    ParserStatusEnum,
)


class JuniperParser(BaseParser):
    """Deterministic parser for Juniper Junos set-style and hierarchical configurations."""

    def parse(self, file_id: str, content: str, device_type: str, vendor: str = "Juniper") -> ParsedConfiguration:
        lines = content.split("\n")
        evidence: List[ParsedEvidenceItem] = []

        data: Dict[str, Any] = {
            "hostname": None,
            "interfaces": [],
            "routing": {
                "static_routes": [],
                "ospf": False,
                "bgp": False,
            },
            "security": {
                "zones": [],
                "policies": [],
            },
            "management": {
                "ssh_enabled": False,
                "services": [],
            },
            "ntp": {
                "servers": [],
            },
            "syslog": {
                "hosts": [],
            },
        }

        # Trackers for set-style and hierarchical blocks
        interfaces_map: Dict[str, Dict[str, Any]] = {}
        hierarchical_path: List[str] = []

        for idx, line in enumerate(lines, start=1):
            sline = line.strip()
            if not sline or sline.startswith("#") or sline.startswith("/*"):
                continue

            # ─────────────────────────────────────────────────────────────────
            # A. SET-STYLE JUNOS PARSING
            # ─────────────────────────────────────────────────────────────────
            if sline.startswith("set "):
                # 1. Hostname
                m_host = re.match(r"^set\s+system\s+host-name\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", sline, re.IGNORECASE)
                if m_host:
                    data["hostname"] = m_host.group(1)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="hostname"))
                    continue

                # 2. Interfaces
                m_if = re.match(r"^set\s+interfaces\s+([A-Za-z0-9\/\-]+)(?:\s+unit\s+(\d+))?(?:\s+family\s+([A-Za-z0-9]+))?(?:\s+address\s+([0-9\.\/]+))?", sline, re.IGNORECASE)
                if m_if:
                    ifname = m_if.group(1)
                    unit = m_if.group(2) or "0"
                    family = m_if.group(3) or "inet"
                    ip_addr = m_if.group(4)

                    key = f"{ifname}.{unit}"
                    if key not in interfaces_map:
                        interfaces_map[key] = {
                            "name": ifname,
                            "unit": int(unit),
                            "family": family,
                            "ip_addresses": [],
                            "description": None,
                            "enabled": True,
                        }
                    if ip_addr:
                        interfaces_map[key]["ip_addresses"].append(ip_addr)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{key}"))
                    continue

                m_if_desc = re.match(r"^set\s+interfaces\s+([A-Za-z0-9\/\-]+)\s+description\s+[\"']?(.+?)[\"']?$", sline, re.IGNORECASE)
                if m_if_desc:
                    ifname = m_if_desc.group(1)
                    key = f"{ifname}.0"
                    if key not in interfaces_map:
                        interfaces_map[key] = {"name": ifname, "unit": 0, "family": "inet", "ip_addresses": [], "description": m_if_desc.group(2), "enabled": True}
                    else:
                        interfaces_map[key]["description"] = m_if_desc.group(2)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{ifname}.description"))
                    continue

                # 3. Security Zones & Policies
                m_zone = re.match(r"^set\s+security\s+zones\s+security-zone\s+([A-Za-z0-9_\-]+)(?:\s+interfaces\s+([A-Za-z0-9\/\.-]+))?", sline, re.IGNORECASE)
                if m_zone:
                    zname = m_zone.group(1)
                    if zname not in [z["name"] for z in data["security"]["zones"]]:
                        data["security"]["zones"].append({"name": zname, "interfaces": []})
                    if m_zone.group(2):
                        z_obj = next(z for z in data["security"]["zones"] if z["name"] == zname)
                        z_obj["interfaces"].append(m_zone.group(2))
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"security.zones.{zname}"))
                    continue

                m_policy = re.match(r"^set\s+security\s+policies\s+from-zone\s+([A-Za-z0-9_\-]+)\s+to-zone\s+([A-Za-z0-9_\-]+)\s+policy\s+([A-Za-z0-9_\-]+)", sline, re.IGNORECASE)
                if m_policy:
                    pname = m_policy.group(3)
                    if pname not in [p["name"] for p in data["security"]["policies"]]:
                        data["security"]["policies"].append({
                            "name": pname,
                            "from_zone": m_policy.group(1),
                            "to_zone": m_policy.group(2),
                            "action": "permit" if "then permit" in sline.lower() else "deny",
                        })
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"security.policies.{pname}"))
                    continue

                # 4. Routing
                m_route = re.match(r"^set\s+routing-options\s+static\s+route\s+([0-9\.\/]+)\s+next-hop\s+([0-9\.]+)", sline, re.IGNORECASE)
                if m_route:
                    data["routing"]["static_routes"].append({"destination": m_route.group(1), "next_hop": m_route.group(2)})
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.static_routes"))
                    continue

                if re.match(r"^set\s+protocols\s+ospf\b", sline, re.IGNORECASE):
                    data["routing"]["ospf"] = True
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.ospf"))
                    continue

                if re.match(r"^set\s+protocols\s+bgp\b", sline, re.IGNORECASE):
                    data["routing"]["bgp"] = True
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.bgp"))
                    continue

                # 5. Management / SSH
                if re.match(r"^set\s+system\s+services\s+ssh\b", sline, re.IGNORECASE):
                    data["management"]["ssh_enabled"] = True
                    if "ssh" not in data["management"]["services"]:
                        data["management"]["services"].append("ssh")
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="management.ssh_enabled"))
                    continue

                # 6. NTP & Syslog
                m_ntp = re.match(r"^set\s+system\s+ntp\s+server\s+([0-9\.]+|[A-Za-z0-9_\-\.]+)", sline, re.IGNORECASE)
                if m_ntp:
                    data["ntp"]["servers"].append(m_ntp.group(1))
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="ntp.servers"))
                    continue

                m_sys = re.match(r"^set\s+system\s+syslog\s+host\s+([0-9\.]+|[A-Za-z0-9_\-\.]+)", sline, re.IGNORECASE)
                if m_sys:
                    data["syslog"]["hosts"].append(m_sys.group(1))
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="syslog.hosts"))
                    continue

            # ─────────────────────────────────────────────────────────────────
            # B. HIERARCHICAL JUNOS PARSING ({})
            # ─────────────────────────────────────────────────────────────────
            else:
                m_host_h = re.match(r"^\s*host-name\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?;", sline, re.IGNORECASE)
                if m_host_h:
                    data["hostname"] = m_host_h.group(1)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="hostname"))
                    continue

                m_addr_h = re.match(r"^\s*address\s+([0-9\.\/]+);", sline, re.IGNORECASE)
                if m_addr_h and "interfaces" in hierarchical_path:
                    # Find outer interface block if possible
                    ifname = next((p for p in reversed(hierarchical_path) if "-" in p), "ge-0/0/0")
                    key = f"{ifname}.0"
                    if key not in interfaces_map:
                        interfaces_map[key] = {"name": ifname, "unit": 0, "family": "inet", "ip_addresses": [], "description": None, "enabled": True}
                    interfaces_map[key]["ip_addresses"].append(m_addr_h.group(1))
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{key}"))
                    continue

                if re.match(r"^\s*ssh\s*;", sline, re.IGNORECASE) and "services" in hierarchical_path:
                    data["management"]["ssh_enabled"] = True
                    if "ssh" not in data["management"]["services"]:
                        data["management"]["services"].append("ssh")
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="management.ssh_enabled"))
                    continue

                # Path tracking for hierarchical blocks
                if "{" in sline:
                    block_name = sline.split("{")[0].strip()
                    if block_name:
                        hierarchical_path.append(block_name)
                if "}" in sline and hierarchical_path:
                    hierarchical_path.pop()

        data["interfaces"] = list(interfaces_map.values())

        return ParsedConfiguration(
            file_id=file_id,
            vendor=vendor,
            device_type=device_type,
            status=ParserStatusEnum.PARSED,
            parser="JuniperParser",
            data=data,
            evidence=evidence,
        )
