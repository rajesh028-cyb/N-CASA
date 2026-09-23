"""
N-CASA Normalization Repository
"""

from typing import List, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.normalization import NormalizedConfigurationModel


class NormalizationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_normalized_configs(self, audit_id: str, configs_data: List[Dict[str, Any]]) -> List[NormalizedConfigurationModel]:
        await self.session.execute(
            delete(NormalizedConfigurationModel).where(NormalizedConfigurationModel.audit_id == audit_id)
        )
        models = []
        for item in configs_data:
            model = NormalizedConfigurationModel(
                audit_id=audit_id,
                file_id=item["file_id"],
                normalization_method=item.get("normalization_method", "DETERMINISTIC"),
                requires_manual_validation=item.get("requires_manual_validation", False),
                confidence=item.get("confidence", 1.0),
                normalized_data=item.get("normalized_data")
            )
            self.session.add(model)
            models.append(model)
        await self.session.flush()
        return models

    async def get_normalized_configs(self, audit_id: str) -> List[NormalizedConfigurationModel]:
        stmt = select(NormalizedConfigurationModel).where(NormalizedConfigurationModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
