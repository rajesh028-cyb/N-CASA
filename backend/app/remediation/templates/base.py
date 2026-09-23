"""
N-CASA Base Remediation Template
==================================
Abstract base class for vendor-specific remediation templates.
"""

from typing import Any, Dict, List
from app.findings.models import FindingRecord
from app.remediation.models import RemediationRecord, RemediationStatusEnum, ReviewStatusEnum


class BaseRemediationTemplate:
    """Base class for control remediation templates."""

    control_id: str
    vendor: str

    def generate(self, finding: FindingRecord) -> RemediationRecord:
        """Generate a structured remediation suggestion record for a finding."""
        raise NotImplementedError("Subclasses must implement generate()")

    @staticmethod
    def _default_validation_steps(control_id: str) -> List[str]:
        return [
          "Review the proposed configuration snippet with an authorized network engineer.",
          "Apply the configuration change in a non-production test environment.",
          "Re-run N-CASA compliance evaluation for the target device configuration.",
          f"Verify that control {control_id} status changes from FAIL to PASS.",
        ]

    @staticmethod
    def _default_rollback_guidance() -> str:
        return "Restore previous device configuration from the organization's approved backup/change-control repository."
