"""
N-CASA Vendor-Neutral Normalization Package
"""

from app.normalization.models import (
    AuditNormalizationSummary,
    NormalizationStatusEnum,
    NormalizedACL,
    NormalizedAuthentication,
    NormalizedConfiguration,
    NormalizedEvidenceItem,
    NormalizedFirewallPolicy,
    NormalizedIdentity,
    NormalizedInterface,
    NormalizedLogging,
    NormalizedManagement,
    NormalizedNTP,
    NormalizedRouting,
    NormalizedSecurityZone,
    NormalizedVLAN,
    NormalizedVPN,
)
from app.normalization.normalizer import BaseNormalizer, format_ip_cidr, netmask_to_prefix
from app.normalization.cisco_normalizer import CiscoNormalizer
from app.normalization.juniper_normalizer import JuniperNormalizer
from app.normalization.fortinet_normalizer import FortinetNormalizer
from app.normalization.registry import NormalizerRegistry, normalizer_registry

__all__ = [
    "AuditNormalizationSummary",
    "NormalizationStatusEnum",
    "NormalizedConfiguration",
    "NormalizedEvidenceItem",
    "NormalizedIdentity",
    "NormalizedManagement",
    "NormalizedAuthentication",
    "NormalizedInterface",
    "NormalizedRouting",
    "NormalizedVLAN",
    "NormalizedACL",
    "NormalizedFirewallPolicy",
    "NormalizedSecurityZone",
    "NormalizedLogging",
    "NormalizedNTP",
    "NormalizedVPN",
    "BaseNormalizer",
    "format_ip_cidr",
    "netmask_to_prefix",
    "CiscoNormalizer",
    "JuniperNormalizer",
    "FortinetNormalizer",
    "NormalizerRegistry",
    "normalizer_registry",
]
