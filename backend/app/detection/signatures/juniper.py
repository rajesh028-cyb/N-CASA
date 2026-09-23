"""
Juniper Vendor Signatures & Device Type Rules
=============================================
Supports Junos `set` syntax and hierarchical `{}` syntax.
"""

import re
from app.models.detection import DeviceTypeEnum, EvidenceCategory, VendorEnum

JUNIPER_SIGNATURES = [
    # ── STRONG INDICATORS (+50 points) ───────────────────────────────────────
    (re.compile(r"^\s*set\s+system\s+host-name\b", re.IGNORECASE), "set system host-name", EvidenceCategory.STRONG),
    (re.compile(r"^\s*set\s+interfaces\s+(?:ge-|xe-|et-|fe-)", re.IGNORECASE), "set interfaces ge-/xe-", EvidenceCategory.STRONG),
    (re.compile(r"^\s*set\s+security\s+policies\b", re.IGNORECASE), "set security policies", EvidenceCategory.STRONG),
    (re.compile(r"^\s*set\s+security\s+zones\b", re.IGNORECASE), "set security zones", EvidenceCategory.STRONG),
    (re.compile(r"^\s*set\s+routing-options\b", re.IGNORECASE), "set routing-options", EvidenceCategory.STRONG),
    (re.compile(r"^\s*set\s+protocols\s+(?:ospf|bgp|ldp|rsvp)\b", re.IGNORECASE), "set protocols ospf/bgp", EvidenceCategory.STRONG),
    (re.compile(r"^\s*host-name\s+[A-Za-z0-9_\-\.]+;", re.IGNORECASE), "host-name <name>;", EvidenceCategory.STRONG),

    # ── MEDIUM INDICATORS (+20 points) ──────────────────────────────────────
    (re.compile(r"^\s*set\s+chassis\b", re.IGNORECASE), "set chassis", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*set\s+system\s+services\b", re.IGNORECASE), "set system services", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*set\s+system\s+root-authentication\b", re.IGNORECASE), "set system root-authentication", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*(?:ge|xe|et|fe)-\d+/\d+/\d+\s*\{", re.IGNORECASE), "ge-0/0/0 {", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*family\s+ethernet-switching;", re.IGNORECASE), "family ethernet-switching;", EvidenceCategory.MEDIUM),
]


def detect_juniper_device_type(text: str) -> DeviceTypeEnum:
    """Determine if a Juniper device is a Router, Switch, Firewall, or Unknown."""
    firewall_score = 0
    router_score = 0
    switch_score = 0

    lines = text.split("\n")
    for line in lines:
        sline = line.strip()
        if "set security zones" in sline or "set security policies" in sline or "security {" in sline:
            firewall_score += 4
        if "set protocols bgp" in sline or "set protocols ospf" in sline or "set routing-options" in sline:
            router_score += 3
        if "family ethernet-switching" in sline or "set vlans" in sline or "vlans {" in sline:
            switch_score += 4

    if firewall_score >= 4:
        return DeviceTypeEnum.FIREWALL
    if switch_score >= 4:
        return DeviceTypeEnum.SWITCH
    if router_score >= 3:
        return DeviceTypeEnum.ROUTER

    return DeviceTypeEnum.UNKNOWN
