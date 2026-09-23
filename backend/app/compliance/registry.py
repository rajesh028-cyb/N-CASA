"""
N-CASA Compliance Rule Registry
=================================
Central registry mapping rule implementations to control IDs and frameworks.
"""

from typing import Dict, List, Optional
from app.compliance.models import ControlMetadata
from app.compliance.rules.base import BaseComplianceRule
from app.compliance.rules.cis import (
    CIS_ACL_Rule,
    CIS_FirewallPolicy_Rule,
    CIS_Hostname_Rule,
    CIS_HTTP_Rule,
    CIS_HTTPS_Rule,
    CIS_InterfaceState_Rule,
    CIS_SSH_Rule,
    CIS_Telnet_Rule,
)
from app.compliance.rules.nist import (
    NIST_AAA_Rule,
    NIST_Logging_Rule,
    NIST_NTP_Rule,
    NIST_VPN_Rule,
)
from app.compliance.rules.stig import STIG_Routing_Rule


class ComplianceRuleRegistry:
    """Registry managing active compliance rule instances."""

    def __init__(self):
        self._rules: Dict[str, BaseComplianceRule] = {}
        self._register_default_rules()

    def _register_default_rules(self):
        """Instantiate and register default initial 13 controls."""
        rules_list: List[BaseComplianceRule] = [
            CIS_SSH_Rule(),
            CIS_Telnet_Rule(),
            CIS_HTTP_Rule(),
            CIS_HTTPS_Rule(),
            CIS_Hostname_Rule(),
            CIS_InterfaceState_Rule(),
            CIS_FirewallPolicy_Rule(),
            CIS_ACL_Rule(),
            NIST_AAA_Rule(),
            NIST_Logging_Rule(),
            NIST_NTP_Rule(),
            NIST_VPN_Rule(),
            STIG_Routing_Rule(),
        ]
        for rule in rules_list:
            self._rules[rule.control_id.upper()] = rule

    def register_rule(self, rule: BaseComplianceRule):
        """Register a new or custom compliance rule."""
        self._rules[rule.control_id.upper()] = rule

    def get_rules(self, framework: Optional[str] = None) -> List[BaseComplianceRule]:
        """
        Get registered rules. If framework is specified (e.g. CIS, NIST, STIG),
        returns only rules matching that framework.
        """
        if not framework:
            return list(self._rules.values())
        fw_upper = framework.strip().upper()
        return [r for r in self._rules.values() if r.framework.upper() == fw_upper]

    def get_rule(self, control_id: str) -> Optional[BaseComplianceRule]:
        """Lookup rule instance by control ID (case-insensitive)."""
        return self._rules.get(control_id.strip().upper())


# Global singleton instance
compliance_rule_registry = ComplianceRuleRegistry()
