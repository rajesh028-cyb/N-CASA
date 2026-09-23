"""
Cisco IOS / IOS-XE / NX-OS Configuration Parser
================================================
Converts raw Cisco configuration text into structured vendor data with source line numbers.
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


class CiscoParser(BaseParser):
    """Deterministic parser for Cisco IOS, IOS-XE, and NX-OS configurations."""

    def parse(self, file_id: str, content: str, device_type: str, vendor: str = "Cisco") -> ParsedConfiguration:
        lines = content.split("\n")
        evidence: List[ParsedEvidenceItem] = []

        data: Dict[str, Any] = {
            "hostname": None,
            "interfaces": [],
            "routing": {
                "ospf": None,
                "bgp": None,
                "eigrp": None,
                "static_routes": [],
            },
            "vlans": [],
            "acls": [],
            "management": {
                "ssh_version": None,
                "line_vty": [],
            },
            "authentication": {
                "usernames": [],
                "enable_secret": False,
                "aaa_new_model": False,
                "aaa_rules": [],
            },
            "logging": {
                "hosts": [],
                "buffered": None,
            },
            "ntp": {
                "servers": [],
            },
        }

        # Context trackers
        current_interface: Optional[Dict[str, Any]] = None
        current_vlan: Optional[Dict[str, Any]] = None
        current_acl: Optional[Dict[str, Any]] = None
        current_vty: Optional[Dict[str, Any]] = None
        current_ospf: Optional[Dict[str, Any]] = None

        for idx, line in enumerate(lines, start=1):
            sline = line.strip()
            if not sline or sline.startswith("!"):
                continue

            # 1. Hostname
            m_host = re.match(r"^hostname\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", sline, re.IGNORECASE)
            if m_host:
                data["hostname"] = m_host.group(1)
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="hostname"))
                continue

            # 2. Interfaces
            m_if = re.match(r"^interface\s+([A-Za-z0-9\/\.\:]+)", sline, re.IGNORECASE)
            if m_if:
                if current_interface:
                    data["interfaces"].append(current_interface)
                current_interface = {
                    "name": m_if.group(1),
                    "description": None,
                    "ip_addresses": [],
                    "shutdown": False,
                    "switchport": {
                        "mode": None,
                        "access_vlan": None,
                        "native_vlan": None,
                        "allowed_vlans": [],
                    },
                }
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{m_if.group(1)}"))
                continue

            if current_interface and line.startswith(" "):
                m_desc = re.match(r"^\s*description\s+(.+)$", sline, re.IGNORECASE)
                if m_desc:
                    current_interface["description"] = m_desc.group(1)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.description"))
                    continue

                m_ip = re.match(r"^\s*ip\s+address\s+([0-9\.]+)\s+([0-9\.]+)", sline, re.IGNORECASE)
                if m_ip:
                    current_interface["ip_addresses"].append({"ip": m_ip.group(1), "netmask": m_ip.group(2)})
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.ip_address"))
                    continue

                if re.match(r"^\s*shutdown\b", sline, re.IGNORECASE):
                    current_interface["shutdown"] = True
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.shutdown"))
                    continue

                m_sw_mode = re.match(r"^\s*switchport\s+mode\s+(access|trunk|dynamic)", sline, re.IGNORECASE)
                if m_sw_mode:
                    current_interface["switchport"]["mode"] = m_sw_mode.group(1).lower()
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.switchport.mode"))
                    continue

                m_acc_vlan = re.match(r"^\s*switchport\s+access\s+vlan\s+(\d+)", sline, re.IGNORECASE)
                if m_acc_vlan:
                    current_interface["switchport"]["access_vlan"] = int(m_acc_vlan.group(1))
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.switchport.access_vlan"))
                    continue

                m_nat_vlan = re.match(r"^\s*switchport\s+trunk\s+native\s+vlan\s+(\d+)", sline, re.IGNORECASE)
                if m_nat_vlan:
                    current_interface["switchport"]["native_vlan"] = int(m_nat_vlan.group(1))
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.switchport.native_vlan"))
                    continue

                m_allow_vlan = re.match(r"^\s*switchport\s+trunk\s+allowed\s+vlan\s+(add\s+)?([0-9\,-]+)", sline, re.IGNORECASE)
                if m_allow_vlan:
                    vlans_raw = m_allow_vlan.group(2)
                    current_interface["switchport"]["allowed_vlans"].extend([v.strip() for v in vlans_raw.split(",")])
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_interface['name']}.switchport.allowed_vlans"))
                    continue

            # 3. VLAN definitions
            m_vlan = re.match(r"^vlan\s+(\d+)", sline, re.IGNORECASE)
            if m_vlan:
                if current_interface:
                    data["interfaces"].append(current_interface)
                    current_interface = None
                if current_vlan:
                    data["vlans"].append(current_vlan)
                current_vlan = {"vlan_id": int(m_vlan.group(1)), "name": f"VLAN{m_vlan.group(1)}"}
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"vlans.{m_vlan.group(1)}"))
                continue

            if current_vlan and line.startswith(" "):
                m_vname = re.match(r"^\s*name\s+(.+)$", sline, re.IGNORECASE)
                if m_vname:
                    current_vlan["name"] = m_vname.group(1)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"vlans.{current_vlan['vlan_id']}.name"))
                    continue

            # Reset section tracking on non-indented lines
            if not line.startswith(" ") and not sline.startswith("!"):
                if current_interface:
                    data["interfaces"].append(current_interface)
                    current_interface = None
                if current_vlan:
                    data["vlans"].append(current_vlan)
                    current_vlan = None

            # 4. Routing
            m_route = re.match(r"^ip\s+route\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.|[A-Za-z0-9]+)", sline, re.IGNORECASE)
            if m_route:
                data["routing"]["static_routes"].append({
                    "destination": m_route.group(1),
                    "netmask": m_route.group(2),
                    "next_hop": m_route.group(3),
                })
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.static_routes"))
                continue

            m_ospf = re.match(r"^router\s+ospf\s+(\d+)", sline, re.IGNORECASE)
            if m_ospf:
                data["routing"]["ospf"] = {"process_id": int(m_ospf.group(1)), "networks": []}
                current_ospf = data["routing"]["ospf"]
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.ospf"))
                continue

            if current_ospf and line.startswith(" "):
                m_net = re.match(r"^\s*network\s+([0-9\.]+)\s+([0-9\.]+)\s+area\s+(\d+)", sline, re.IGNORECASE)
                if m_net:
                    current_ospf["networks"].append({"network": m_net.group(1), "wildcard": m_net.group(2), "area": int(m_net.group(3))})
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.ospf.networks"))
                    continue

            m_bgp = re.match(r"^router\s+bgp\s+(\d+)", sline, re.IGNORECASE)
            if m_bgp:
                data["routing"]["bgp"] = {"as_number": int(m_bgp.group(1))}
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.bgp"))
                continue

            m_eigrp = re.match(r"^router\s+eigrp\s+(\d+)", sline, re.IGNORECASE)
            if m_eigrp:
                data["routing"]["eigrp"] = {"as_number": int(m_eigrp.group(1))}
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="routing.eigrp"))
                continue

            # 5. ACLs
            m_std_acl = re.match(r"^access-list\s+(\d+)\s+(permit|deny)\s+(.+)", sline, re.IGNORECASE)
            if m_std_acl:
                data["acls"].append({
                    "name": m_std_acl.group(1),
                    "type": "standard",
                    "rule": f"{m_std_acl.group(2)} {m_std_acl.group(3)}",
                })
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"acls.{m_std_acl.group(1)}"))
                continue

            m_ext_acl = re.match(r"^ip\s+access-list\s+(standard|extended)\s+(.+)", sline, re.IGNORECASE)
            if m_ext_acl:
                data["acls"].append({
                    "name": m_ext_acl.group(2),
                    "type": m_ext_acl.group(1).lower(),
                    "rules": [],
                })
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"acls.{m_ext_acl.group(2)}"))
                continue

            # 6. Management & SSH
            m_ssh = re.match(r"^ip\s+ssh\s+version\s+(\d+)", sline, re.IGNORECASE)
            if m_ssh:
                data["management"]["ssh_version"] = m_ssh.group(1)
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="management.ssh_version"))
                continue

            m_vty = re.match(r"^line\s+vty\s+(\d+)\s+(\d+)", sline, re.IGNORECASE)
            if m_vty:
                current_vty = {"range": f"{m_vty.group(1)}-{m_vty.group(2)}", "transport_input": None, "login_local": False}
                data["management"]["line_vty"].append(current_vty)
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="management.line_vty"))
                continue

            if current_vty and line.startswith(" "):
                m_tr = re.match(r"^\s*transport\s+input\s+(.+)", sline, re.IGNORECASE)
                if m_tr:
                    current_vty["transport_input"] = m_tr.group(1)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="management.line_vty.transport_input"))
                    continue
                if re.match(r"^\s*login\s+local\b", sline, re.IGNORECASE):
                    current_vty["login_local"] = True
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="management.line_vty.login_local"))
                    continue

            # 7. Authentication / AAA
            m_user = re.match(r"^username\s+([A-Za-z0-9_\-]+)\s+.*?\bprivilege\s+(\d+)", sline, re.IGNORECASE)
            if m_user:
                data["authentication"]["usernames"].append({"username": m_user.group(1), "privilege": int(m_user.group(2))})
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="authentication.usernames"))
                continue

            if re.match(r"^enable\s+secret\b", sline, re.IGNORECASE):
                data["authentication"]["enable_secret"] = True
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="authentication.enable_secret"))
                continue

            if re.match(r"^aaa\s+new-model\b", sline, re.IGNORECASE):
                data["authentication"]["aaa_new_model"] = True
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="authentication.aaa_new_model"))
                continue

            # 8. Logging
            m_log_host = re.match(r"^logging\s+host\s+([0-9\.]+|[A-Za-z0-9_\-\.]+)", sline, re.IGNORECASE)
            if m_log_host:
                data["logging"]["hosts"].append(m_log_host.group(1))
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="logging.hosts"))
                continue

            m_log_buf = re.match(r"^logging\s+buffered\s+(.+)", sline, re.IGNORECASE)
            if m_log_buf:
                data["logging"]["buffered"] = m_log_buf.group(1)
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="logging.buffered"))
                continue

            # 9. NTP
            m_ntp = re.match(r"^ntp\s+server\s+([0-9\.]+|[A-Za-z0-9_\-\.]+)", sline, re.IGNORECASE)
            if m_ntp:
                data["ntp"]["servers"].append(m_ntp.group(1))
                evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="ntp.servers"))
                continue

        # Append remaining open block items
        if current_interface:
            data["interfaces"].append(current_interface)
        if current_vlan:
            data["vlans"].append(current_vlan)

        return ParsedConfiguration(
            file_id=file_id,
            vendor=vendor,
            device_type=device_type,
            status=ParserStatusEnum.PARSED,
            parser="CiscoParser",
            data=data,
            evidence=evidence,
        )
