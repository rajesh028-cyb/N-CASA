"""
Fortinet FortiOS Configuration Parser
=======================================
Converts FortiOS configuration text into structured vendor data with source line numbers.
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


class FortinetParser(BaseParser):
    """Deterministic parser for Fortinet FortiOS configurations."""

    def parse(self, file_id: str, content: str, device_type: str, vendor: str = "Fortinet") -> ParsedConfiguration:
        lines = content.split("\n")
        evidence: List[ParsedEvidenceItem] = []

        data: Dict[str, Any] = {
            "hostname": None,
            "vdom": None,
            "interfaces": [],
            "firewall_policies": [],
            "address_objects": [],
            "static_routes": [],
            "vpn": {
                "configured": False,
                "sections": [],
            },
            "logging": {
                "configured": False,
                "targets": [],
            },
            "ntp": {
                "servers": [],
            },
        }

        current_config_block: Optional[str] = None
        current_item: Optional[Dict[str, Any]] = None

        for idx, line in enumerate(lines, start=1):
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue

            # Section entry: config <section>
            m_cfg = re.match(r"^config\s+(.+)$", sline, re.IGNORECASE)
            if m_cfg:
                current_config_block = m_cfg.group(1).lower().strip()
                if "vpn" in current_config_block:
                    data["vpn"]["configured"] = True
                    data["vpn"]["sections"].append(current_config_block)
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="vpn"))
                elif "log" in current_config_block:
                    data["logging"]["configured"] = True
                    evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="logging"))
                continue

            # Section exit: end
            if sline == "end":
                if current_item and current_config_block:
                    self._save_current_item(data, current_config_block, current_item)
                    current_item = None
                current_config_block = None
                continue

            # Sub-item entry: edit <id_or_name>
            m_edit = re.match(r"^edit\s+[\"']?([^\"']+)[\"']?", sline, re.IGNORECASE)
            if m_edit:
                if current_item and current_config_block:
                    self._save_current_item(data, current_config_block, current_item)
                current_item = {"id": m_edit.group(1)}
                continue

            # Sub-item exit: next
            if sline == "next":
                if current_item and current_config_block:
                    self._save_current_item(data, current_config_block, current_item)
                    current_item = None
                continue

            # Parameter entry: set <key> <val>
            m_set = re.match(r"^set\s+([A-Za-z0-9_\-]+)\s+(.+)$", sline, re.IGNORECASE)
            if m_set:
                key = m_set.group(1).lower()
                val = m_set.group(2).strip().strip('"')

                # Global identity settings
                if current_config_block == "system global":
                    if key == "hostname":
                        data["hostname"] = val
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="hostname"))
                    elif key == "vdom":
                        data["vdom"] = val
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="vdom"))
                    continue

                # Logging settings
                if current_config_block and "log" in current_config_block:
                    if key in ("server", "server-ip", "syslog-server") or "server" in key:
                        data["logging"]["targets"].append(val)
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="logging.targets"))
                        continue
                    elif key == "status" and val.lower() == "enable":
                        data["logging"]["configured"] = True
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="logging.status"))
                        continue

                # NTP settings
                if current_config_block and ("ntp" in current_config_block or "server" in current_config_block):
                    if key in ("server", "ntpserver") or "server" in key:
                        data["ntp"]["servers"].append(val)
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field="ntp.servers"))
                        continue

                # Item-level setting within a block (e.g. edit "port1")
                if current_item:
                    current_item[key] = val
                    if current_config_block == "system interface" and key == "ip":
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"interfaces.{current_item.get('id')}.ip"))
                    elif current_config_block == "firewall policy" and key == "action":
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"firewall_policies.{current_item.get('id')}.action"))
                    elif current_config_block == "firewall address" and key == "subnet":
                        evidence.append(ParsedEvidenceItem(line=idx, text=sline, field=f"address_objects.{current_item.get('id')}.subnet"))

        return ParsedConfiguration(
            file_id=file_id,
            vendor=vendor,
            device_type=device_type,
            status=ParserStatusEnum.PARSED,
            parser="FortinetParser",
            data=data,
            evidence=evidence,
        )

    def _save_current_item(self, data: Dict[str, Any], block: str, item: Dict[str, Any]) -> None:
        if block == "system interface":
            data["interfaces"].append({
                "name": item.get("id"),
                "ip": item.get("ip"),
                "allowaccess": item.get("allowaccess", "").split() if item.get("allowaccess") else [],
                "description": item.get("description"),
                "status": item.get("status", "up"),
            })
        elif block == "firewall policy":
            data["firewall_policies"].append({
                "policy_id": item.get("id"),
                "name": item.get("name"),
                "srcintf": item.get("srcintf"),
                "dstintf": item.get("dstintf"),
                "srcaddr": item.get("srcaddr"),
                "dstaddr": item.get("dstaddr"),
                "action": item.get("action", "accept"),
                "service": item.get("service"),
                "schedule": item.get("schedule"),
                "logtraffic": item.get("logtraffic"),
            })
        elif block == "firewall address":
            data["address_objects"].append({
                "name": item.get("id"),
                "subnet": item.get("subnet") or item.get("ip"),
                "type": item.get("type", "ipmask"),
            })
        elif block == "router static":
            data["static_routes"].append({
                "id": item.get("id"),
                "dst": item.get("dst"),
                "gateway": item.get("gateway"),
                "device": item.get("device"),
                "distance": item.get("distance"),
            })
