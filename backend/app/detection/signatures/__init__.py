"""
Vendor Signatures Registry
"""

from app.detection.signatures.cisco import CISCO_SIGNATURES, detect_cisco_device_type
from app.detection.signatures.juniper import JUNIPER_SIGNATURES, detect_juniper_device_type
from app.detection.signatures.fortinet import FORTINET_SIGNATURES, detect_fortinet_device_type

__all__ = [
    "CISCO_SIGNATURES",
    "detect_cisco_device_type",
    "JUNIPER_SIGNATURES",
    "detect_juniper_device_type",
    "FORTINET_SIGNATURES",
    "detect_fortinet_device_type",
]
