"""
N-CASA AI Repository
"""

from typing import List, Dict, Any, Optional
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.ai_analysis import AIAnalysisResultModel, AIExplanationModel


class AIRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_ai_analysis_results(self, audit_id: str, results_data: List[Dict[str, Any]]) -> List[AIAnalysisResultModel]:
        await self.session.execute(
            delete(AIAnalysisResultModel).where(AIAnalysisResultModel.audit_id == audit_id)
        )
        models = []
        for item in results_data:
            model = AIAnalysisResultModel(
                audit_id=audit_id,
                file_id=item.get("file_id", "file_0"),
                analysis_method=item.get("analysis_method", "AI_ASSISTED"),
                vendor_hypothesis=item.get("vendor_hypothesis", "UNKNOWN"),
                device_type=item.get("device_type", "UNKNOWN"),
                confidence=item.get("confidence", 0.0),
                normalized_output=item.get("normalized_output"),
                requires_manual_validation=item.get("requires_manual_validation", True)
            )
            self.session.add(model)
            models.append(model)
        await self.session.flush()
        return models

    async def get_ai_analysis_results(self, audit_id: str) -> List[AIAnalysisResultModel]:
        stmt = select(AIAnalysisResultModel).where(AIAnalysisResultModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def save_ai_explanation(self, audit_id: str, item: Dict[str, Any]) -> AIExplanationModel:
        model = AIExplanationModel(
            audit_id=audit_id,
            finding_id=item.get("finding_id", ""),
            summary=item.get("summary", ""),
            security_impact=item.get("security_impact", ""),
            evidence_interpretation=item.get("evidence_interpretation", ""),
            recommended_review=item.get("recommended_review", ""),
            confidence=item.get("confidence", 0.9)
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def get_ai_explanations(self, audit_id: str) -> List[AIExplanationModel]:
        stmt = select(AIExplanationModel).where(AIExplanationModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
