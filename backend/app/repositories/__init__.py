"""
N-CASA Repositories Package
===========================
Data access layer encapsulating database CRUD operations for all domain entities.
"""

from app.repositories.audit_repository import AuditRepository
from app.repositories.config_repository import ConfigRepository
from app.repositories.detection_repository import DetectionRepository
from app.repositories.parsing_repository import ParsingRepository
from app.repositories.normalization_repository import NormalizationRepository
from app.repositories.compliance_repository import ComplianceRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.remediation_repository import RemediationRepository
from app.repositories.ai_repository import AIRepository
from app.repositories.report_repository import ReportRepository

__all__ = [
    "AuditRepository",
    "ConfigRepository",
    "DetectionRepository",
    "ParsingRepository",
    "NormalizationRepository",
    "ComplianceRepository",
    "FindingRepository",
    "RemediationRepository",
    "AIRepository",
    "ReportRepository",
]
