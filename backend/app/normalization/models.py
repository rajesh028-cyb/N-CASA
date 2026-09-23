"""
N-CASA Vendor-Neutral Security Configuration Models (Pydantic)
===============================================================
Common, vendor-agnostic security configuration schema used by Block 7 Compliance Engine.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NormalizationStatusEnum(str, Enum):
    NORMALIZED = "NORMALIZED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class NormalizedEvidenceItem(BaseModel):
    """Source evidence traceable from normalization field back to raw config line."""
    field: str
    value: Any
    source_vendor: str
    source_file: str
    source_line: Optional[int] = None
    source_text: str
    source: str = "normalizer"


# ── Sub-Models ────────────────────────────────────────────────────────────────

class NormalizedIdentity(BaseModel):
    hostname: Optional[str] = None


class NormalizedSSH(BaseModel):
    enabled: Optional[bool] = None
    version: Optional[str] = None


class NormalizedTelnet(BaseModel):
    enabled: Optional[bool] = None


class NormalizedHTTP(BaseModel):
    enabled: Optional[bool] = None


class NormalizedHTTPS(BaseModel):
    enabled: Optional[bool] = None


class NormalizedManagement(BaseModel):
    ssh: NormalizedSSH = Field(default_factory=NormalizedSSH)
    telnet: NormalizedTelnet = Field(default_factory=NormalizedTelnet)
    http: NormalizedHTTP = Field(default_factory=NormalizedHTTP)
    https: NormalizedHTTPS = Field(default_factory=NormalizedHTTPS)


class NormalizedAuthentication(BaseModel):
    aaa_enabled: Optional[bool] = None
    local_users: List[Dict[str, Any]] = Field(default_factory=list)
    authentication_methods: List[str] = Field(default_factory=list)
    authorization_methods: List[str] = Field(default_factory=list)
    enable_secret_present: Optional[bool] = None  # No plaintext secrets exposed!


class NormalizedInterfaceSwitching(BaseModel):
    mode: Optional[str] = None
    access_vlan: Optional[int] = None
    native_vlan: Optional[int] = None
    allowed_vlans: List[Any] = Field(default_factory=list)


class NormalizedInterface(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: Optional[bool] = None
    ip_addresses: List[str] = Field(default_factory=list)  # CIDR e.g. ["10.0.0.1/24"]
    switching: Optional[NormalizedInterfaceSwitching] = None


class NormalizedRouting(BaseModel):
    static_routes: List[Dict[str, Any]] = Field(default_factory=list)
    ospf_configured: Optional[bool] = None
    bgp_configured: Optional[bool] = None
    eigrp_configured: Optional[bool] = None


class NormalizedVLAN(BaseModel):
    id: int
    name: Optional[str] = None


class NormalizedACLRule(BaseModel):
    action: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    protocol: Optional[str] = None


class NormalizedACL(BaseModel):
    name: str
    type: Optional[str] = None
    rules: List[NormalizedACLRule] = Field(default_factory=list)


class NormalizedFirewallPolicy(BaseModel):
    id: str
    name: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    destination_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    action: Optional[str] = "ACCEPT"
    schedule: Optional[str] = None
    logging_enabled: Optional[bool] = None


class NormalizedSecurityZone(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)


class NormalizedLogging(BaseModel):
    enabled: Optional[bool] = None
    remote_servers: List[str] = Field(default_factory=list)
    local_logging: Optional[bool] = None


class NormalizedNTP(BaseModel):
    enabled: Optional[bool] = None
    servers: List[str] = Field(default_factory=list)


class NormalizedVPN(BaseModel):
    configured: Optional[bool] = None
    types: List[str] = Field(default_factory=list)
    tunnels: List[str] = Field(default_factory=list)


# ── Top-Level Normalized Configuration Model ──────────────────────────────────

class NormalizedConfiguration(BaseModel):
    """Complete vendor-neutral security configuration representation."""
    file_id: str
    vendor: str
    device_type: str
    status: NormalizationStatusEnum = NormalizationStatusEnum.NORMALIZED
    normalizer: str
    normalization_method: str = "DETERMINISTIC"
    identity: NormalizedIdentity = Field(default_factory=NormalizedIdentity)
    management: NormalizedManagement = Field(default_factory=NormalizedManagement)
    authentication: NormalizedAuthentication = Field(default_factory=NormalizedAuthentication)
    interfaces: List[NormalizedInterface] = Field(default_factory=list)
    routing: NormalizedRouting = Field(default_factory=NormalizedRouting)
    vlans: List[NormalizedVLAN] = Field(default_factory=list)
    acls: List[NormalizedACL] = Field(default_factory=list)
    firewall_policies: List[NormalizedFirewallPolicy] = Field(default_factory=list)
    security_zones: List[NormalizedSecurityZone] = Field(default_factory=list)
    logging: NormalizedLogging = Field(default_factory=NormalizedLogging)
    ntp: NormalizedNTP = Field(default_factory=NormalizedNTP)
    vpn: NormalizedVPN = Field(default_factory=NormalizedVPN)
    evidence: List[NormalizedEvidenceItem] = Field(default_factory=list)
    unsupported_reason: Optional[str] = None


class AuditNormalizationSummary(BaseModel):
    """Aggregate normalization summary across all files in an audit."""
    audit_id: str
    status: str
    total_files: int = 0
    normalized_files: int = 0
    partial_files: int = 0
    failed_files: int = 0
    unsupported_files: int = 0
    files: List[NormalizedConfiguration] = Field(default_factory=list)
