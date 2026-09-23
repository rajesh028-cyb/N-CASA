"""
N-CASA Base Normalizer Interface & Conversion Utilities
========================================================
Provides abstract BaseNormalizer interface and network utility functions (e.g. Netmask -> CIDR).
"""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from typing import Optional

from app.normalization.models import NormalizedConfiguration
from app.parsers.base import ParsedConfiguration


def netmask_to_prefix(netmask: str) -> Optional[int]:
    """Convert dotted netmask string (e.g., '255.255.255.0') to CIDR prefix length (e.g., 24)."""
    if not netmask:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask.strip()}").prefixlen
    except Exception:
        return None


def format_ip_cidr(ip: str, netmask: Optional[str] = None) -> str:
    """Format IP and netmask into standard CIDR notation (e.g., '10.0.0.1/24')."""
    if not ip:
        return ""
    ip_clean = ip.strip()

    # Already CIDR notation (e.g., "10.0.0.1/24")
    if "/" in ip_clean:
        return ip_clean

    # Combined string like "10.0.0.1 255.255.255.0"
    parts = ip_clean.split()
    if len(parts) == 2:
        ip_addr, mask = parts[0], parts[1]
        prefix = netmask_to_prefix(mask)
        return f"{ip_addr}/{prefix}" if prefix else ip_clean

    if netmask:
        prefix = netmask_to_prefix(netmask)
        if prefix:
            return f"{ip_clean}/{prefix}"

    return ip_clean


class BaseNormalizer(ABC):
    """Abstract interface for vendor configuration normalizers."""

    @abstractmethod
    def normalize(self, parsed_config: ParsedConfiguration) -> NormalizedConfiguration:
        """Transform vendor-specific parsed data into a vendor-neutral NormalizedConfiguration."""
        pass
