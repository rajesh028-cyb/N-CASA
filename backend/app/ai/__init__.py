"""
N-CASA AI Module
================
Package initialization for Block 10: AI-Assisted Unknown-Vendor Configuration Understanding.
"""

from app.ai.models import (
    AIEvidence,
    AIParsedField,
    AIParsedOutput,
    AIExplanationRecord,
    AIAnalysisFileResult,
    AIAnalysisSummary,
)
from app.ai.provider import BaseAIProvider, MockAIProvider, OpenAICompatibleProvider
from app.ai.validators import redact_secrets, validate_ai_output
from app.ai.service import AIService, ai_service

__all__ = [
    "AIEvidence",
    "AIParsedField",
    "AIParsedOutput",
    "AIExplanationRecord",
    "AIAnalysisFileResult",
    "AIAnalysisSummary",
    "BaseAIProvider",
    "MockAIProvider",
    "OpenAICompatibleProvider",
    "redact_secrets",
    "validate_ai_output",
    "AIService",
    "ai_service",
]
