"""
Base Compliance Rule Contract
===============================
Every rule evaluates a NormalizedConfiguration exclusively (never vendor syntax)
and returns a ComplianceResult (PASS, FAIL, or NOT_VERIFIABLE) with line evidence.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from app.compliance.models import (
    ComplianceEvidence,
    ComplianceResult,
    ComplianceSeverityEnum,
    ComplianceStatusEnum,
    ControlMetadata,
)
from app.normalization.models import NormalizedConfiguration, NormalizedEvidenceItem


class BaseComplianceRule(ABC):
    """Abstract base class for all deterministic compliance rules."""

    def __init__(self, metadata: ControlMetadata):
        self.metadata = metadata

    @property
    def control_id(self) -> str:
        return self.metadata.control_id

    @property
    def framework(self) -> str:
        return self.metadata.framework

    @property
    def title(self) -> str:
        return self.metadata.title

    @property
    def severity(self) -> ComplianceSeverityEnum:
        return self.metadata.severity

    @property
    def category(self) -> str:
        return self.metadata.category

    @property
    def rule_name(self) -> str:
        return self.metadata.rule

    @abstractmethod
    def evaluate(self, config: NormalizedConfiguration) -> ComplianceResult:
        """Evaluate a normalized configuration and return a ComplianceResult."""
        pass

    def filter_evidence(
        self,
        config: NormalizedConfiguration,
        field_prefix: Optional[str] = None
    ) -> List[ComplianceEvidence]:
        """Extract matching evidence items from normalized evidence chain."""
        results: List[ComplianceEvidence] = []
        for ev in config.evidence:
            if field_prefix is None or ev.field.startswith(field_prefix):
                results.append(
                    ComplianceEvidence(
                        field=ev.field,
                        value=ev.value,
                        source_file=ev.source_file,
                        source_line=ev.source_line,
                        source_text=ev.source_text,
                    )
                )
        return results
