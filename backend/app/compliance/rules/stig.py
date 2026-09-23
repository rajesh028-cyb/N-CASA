"""
DISA STIG Framework Compliance Rules
======================================
Deterministic rules for DISA STIG controls.
Operates exclusively on NormalizedConfiguration fields.
"""

from typing import List
from app.compliance.catalog import get_catalog_control_by_id
from app.compliance.models import (
    ComplianceEvidence,
    ComplianceResult,
    ComplianceStatusEnum,
)
from app.compliance.rules.base import BaseComplianceRule
from app.normalization.models import NormalizedConfiguration


class STIG_Routing_Rule(BaseComplianceRule):
    """STIG-NET-ROUTING-001: Dynamic Routing Protocol Configuration Visibility."""

    def __init__(self):
        super().__init__(get_catalog_control_by_id("STIG-NET-ROUTING-001"))

    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        routing = config.routing
        ev = self.filter_evidence(config, "routing")

        has_ospf = routing.ospf_configured is True
        has_bgp = routing.bgp_configured is True
        has_static = len(routing.static_routes) > 0

        if has_ospf or has_bgp or has_static:
            status = ComplianceStatusEnum.PASS
            protocols = []
            if has_ospf: protocols.append("OSPF")
            if has_bgp: protocols.append("BGP")
            if has_static: protocols.append(f"Static Routes ({len(routing.static_routes)})")
            obs = f"Routing configuration visible ({', '.join(protocols)})"
            exp = "Routing protocols and static routes must be clearly defined for security evaluation."
            explanation = "Routing configuration parameters are explicitly structured and visible."
        else:
            status = ComplianceStatusEnum.NOT_VERIFIABLE
            obs = "No dynamic routing or static route entries detected"
            exp = "Routing protocols and static routes must be clearly defined for security evaluation."
            explanation = "Configuration contains no verifiable routing protocol definitions."

        return ComplianceResult(
            control_id=self.control_id,
            framework=self.framework,
            title=self.title,
            description=self.metadata.description,
            severity=self.severity,
            category=self.category,
            status=status,
            expected=exp,
            observed=obs,
            explanation=explanation,
            evidence=ev,
            rule=self.rule_name,
            internal_mapping=True,
        )
