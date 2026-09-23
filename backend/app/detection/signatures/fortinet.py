"""
Fortinet Vendor Signatures & Device Type Rules
===============================================
Supports FortiOS configuration syntax.
"""

import re
from app.models.detection import DeviceTypeEnum, EvidenceCategory, VendorEnum

FORTINET_SIGNATURES = [
    # ── STRONG INDICATORS (+50 points) ───────────────────────────────────────
    (re.compile(r"^\s*config\s+system\s+global\b", re.IGNORECASE), "config system global", EvidenceCategory.STRONG),
    (re.compile(r"^\s*config\s+system\s+interface\b", re.IGNORECASE), "config system interface", EvidenceCategory.STRONG),
    (re.compile(r"^\s*config\s+firewall\s+policy\b", re.IGNORECASE), "config firewall policy", EvidenceCategory.STRONG),
    (re.compile(r"^\s*config\s+router\s+static\b", re.IGNORECASE), "config router static", EvidenceCategory.STRONG),
    (re.compile(r"^\s*config\s+firewall\s+address\b", re.IGNORECASE), "config firewall address", EvidenceCategory.STRONG),
    (re.compile(r"^\s*config\s+vpn\b", re.IGNORECASE), "config vpn", EvidenceCategory.STRONG),

    # ── MEDIUM INDICATORS (+20 points) ──────────────────────────────────────
    (re.compile(r"^\s*config\s+system\s+admin\b", re.IGNORECASE), "config system admin", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*config\s+system\s+vdom\b", re.IGNORECASE), "config system vdom", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*set\s+vdom\b", re.IGNORECASE), "set vdom", EvidenceCategory.MEDIUM),
    (re.compile(r"^\s*set\s+fortiview\b", re.IGNORECASE), "set fortiview", EvidenceCategory.MEDIUM),
]


def detect_fortinet_device_type(text: str) -> DeviceTypeEnum:
    """Determine if a Fortinet device is a Firewall, Security Appliance, or Unknown."""
    firewall_score = 0

    lines = text.split("\n")
    for line in lines:
        sline = line.strip()
        if "config firewall policy" in sline or "config firewall address" in sline or "config vpn" in sline:
            firewall_score += 4
        if "config system global" in sline or "config system interface" in sline:
            firewall_score += 2

    if firewall_score >= 3:
        return DeviceTypeEnum.FIREWALL

    return DeviceTypeEnum.SECURITY_APPLIANCE
