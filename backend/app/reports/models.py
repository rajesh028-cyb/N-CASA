"""
N-CASA Report Data Models (Pydantic)
=====================================
Structured data snapshot model representing a point-in-time audit security report.
Read-only consumer of persisted PostgreSQL audit data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    """Metadata schema for a generated report."""
    report_id: str
    audit_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    report_version: str = "1.0"
    html_path: str = ""
    pdf_path: str = ""


class AuditReport(BaseModel):
    """
    Complete, self-contained audit report snapshot.
    GUARANTEE: Pure snapshot of persisted audit state — no pipeline execution.
    """
    report_id: str
    audit_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    report_version: str = "1.0"

    # Audit Info & Inventory
    audit_metadata: Dict[str, Any] = Field(default_factory=dict)
    inventory_summary: Dict[str, Any] = Field(default_factory=dict)
    files: List[Dict[str, Any]] = Field(default_factory=list)

    # Device & Detection
    device_summary: Dict[str, Any] = Field(default_factory=dict)
    devices: List[Dict[str, Any]] = Field(default_factory=list)

    # Parser & Normalization Metrics
    parsing_summary: Dict[str, Any] = Field(default_factory=dict)
    normalization_summary: Dict[str, Any] = Field(default_factory=dict)

    # Compliance Results
    compliance_summary: Dict[str, Any] = Field(default_factory=dict)
    compliance_results: List[Dict[str, Any]] = Field(default_factory=list)

    # Actionable Findings & Limitations
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    assessment_limitations: List[Dict[str, Any]] = Field(default_factory=list)

    # Remediations (Proposals Only)
    remediation_summary: Dict[str, Any] = Field(default_factory=dict)
    remediation_proposals: List[Dict[str, Any]] = Field(default_factory=list)

    # Advisory AI Analysis (Optional)
    ai_analysis_summary: Optional[Dict[str, Any]] = None
    ai_explanations: List[Dict[str, Any]] = Field(default_factory=list)
