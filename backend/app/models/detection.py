"""
N-CASA Vendor & Device Detection Models (Pydantic)
===================================================
Data transfer objects for deterministic vendor & device type detection.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class VendorEnum(str, Enum):
    CISCO = "Cisco"
    JUNIPER = "Juniper"
    FORTINET = "Fortinet"
    UNKNOWN = "Unknown"


class DeviceTypeEnum(str, Enum):
    ROUTER = "Router"
    SWITCH = "Switch"
    FIREWALL = "Firewall"
    SECURITY_APPLIANCE = "Security Appliance"
    UNKNOWN = "Unknown"


class DetectionMethodEnum(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"


class DetectionStatusEnum(str, Enum):
    KNOWN = "KNOWN"
    UNKNOWN_VENDOR = "UNKNOWN_VENDOR"
    AMBIGUOUS = "AMBIGUOUS"


class EvidenceCategory(str, Enum):
    STRONG = "STRONG"   # +50 points
    MEDIUM = "MEDIUM"   # +20 points
    WEAK = "WEAK"       # +5 points


class EvidenceItem(BaseModel):
    """Line-level evidence supporting a detection decision."""
    indicator: str
    line: int
    category: EvidenceCategory
    vendor: VendorEnum


class VendorDetectionResult(BaseModel):
    """Detection decision and evidence for a single configuration file."""
    file_id: str
    relative_path: str
    vendor: VendorEnum
    device_type: DeviceTypeEnum
    confidence: float = Field(..., ge=0.0, le=1.0, description="Normalized detection confidence (0.00 to 0.99)")
    method: DetectionMethodEnum = DetectionMethodEnum.DETERMINISTIC
    status: DetectionStatusEnum
    evidence: list[EvidenceItem] = Field(default_factory=list)


class AuditDetectionSummary(BaseModel):
    """Aggregate vendor & device detection summary for an audit."""
    audit_id: str
    status: str
    total_files: int = 0
    detected_files: int = 0
    files: list[VendorDetectionResult] = Field(default_factory=list)
