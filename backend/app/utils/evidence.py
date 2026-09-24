"""
N-CASA Evidence Utilities
=========================
Helper functions for formatting and validating evidence objects.
"""

from typing import Any, Dict, List, Optional


def filter_evidence_by_prefix(evidence_list: List[Dict[str, Any]], prefix: str) -> List[Dict[str, Any]]:
    """Filter evidence items where field starts with prefix."""
    return [ev for ev in evidence_list if ev.get("field", "").startswith(prefix)]
