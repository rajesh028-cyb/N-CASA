"""
Cisco Vendor Signatures & Device Type Rules
============================================
Supports Cisco IOS, IOS-XE, and NX-OS signatures.
"""

import re
from app.models.detection import DeviceTypeEnum, EvidenceCategory, VendorEnum

CISCO_SIGNATURES = [
    # ── STRONG INDICATORS (+50 points) ───────────────────────────────────────
    (re.compile(r"^\s*version\s+\d+\.\d+", re.IGNORECASE), "version <number>", EvidenceCategory.STRONG),
    (re.compile(r"^\s*interface\s+(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|TwoGigabitEthernet|FortyGigabitEthernet|HundredGigE|Eth)\b", re.IGNORECASE), "interface GigabitEthernet/FastEthernet/TenGigE", EvidenceCategory.STRONG),
    (re.compile(r"^\s*ip\s+cef\b", re.IGNORECASE), "ip cef", EvidenceCategory.STRONG),
    (re.compile(r"^\s*router\s+(?:ospf|bgp|eigrp|rip)\b", re.IGNORECASE), "router ospf/bgp/eigrp", EvidenceCategory.STRONG),
    (re.compile(r"^\s*ip\s+route\b", re.IGNORECASE), "ip route", EvidenceCategory.STRONG),
    (re.compile(r"^\s*line\s+vty\b", re.IGNORECASE), "line vty", EvidenceCategory.STRONG),
    (re.compile(r"^\s*ip\s+ssh\s+version\b", re.IGNORECASE), "ip ssh version", EvidenceCategory.STRONG),
    (re.compile(r"^\s*boot-start-marker\b", re.IGNORECASE), "boot-start-marker", EvidenceCategory.STRONG),
    (re.compile(r"^\s*crypto\s+isakmp\b", re.IGNORECASE), "crypto isakmp", EvidenceCategory.STRONG),
    (re.compile(r"^\s*snmp-server\s+community\b", re.IGNORECASE), "snmp-server community", EvidenceCategory.STRONG),

    # ── MEDIUM INDICATORS (+20 points) ──────────────────────────────────────
    (re.compile(r"^\s*enable\s+(?:secret|password)\b", re.IGNORECASE), "enable secret/password", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*username\s+.*?\bprivilege\b", re.IGNORECASE), "username ... privilege", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*access-list\s+\d+\b", re.IGNORECASE), "access-list", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*spanning-tree\b", re.IGNORECASE), "spanning-tree", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*no\s+aaa\s+new-model\b", re.IGNORECASE), "no aaa new-model", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*service\s+timestamps\b", re.IGNORECASE), "service timestamps", EvidenceCategory.MEDIUM),
]


def detect_cisco_device_type(text: str) -> DeviceTypeEnum:
    """Determine if a Cisco device is a Router, Switch, Firewall, or Unknown."""
    router_score = 0
    switch_score = 0

    lines = text.split("\n")
    for line in lines:
        sline = line.strip()
        if re.search(r"^\s*router\s+(?:ospf|bgp|eigrp|rip)\b", sline, re.IGNORECASE):
            router_score += 3
        if re.search(r"^\s*ip\s+route\b", sline, re.IGNORECASE):
            router_score += 2
        if re.search(r"^\s*ip\s+routing\b", sline, re.IGNORECASE):
            router_score += 2
        if re.search(r"^\s*interface\s+Loopback", sline, re.IGNORECASE):
            router_score += 1

        if re.search(r"^\s*spanning-tree\b", sline, re.IGNORECASE):
            switch_score += 4
        if re.search(r"^\s*switchport\b", sline, re.IGNORECASE):
            switch_score += 3
        if re.search(r"^\s*vlan\s+\d+\b", sline, re.IGNORECASE):
            switch_score += 3
        if re.search(r"^\s*interface\s+Vlan\d+\b", sline, re.IGNORECASE):
            switch_score += 2

    if switch_score >= 4 and switch_score >= router_score:
        return DeviceTypeEnum.SWITCH
    if router_score >= 3:
        return DeviceTypeEnum.ROUTER

    return DeviceTypeEnum.UNKNOWN
