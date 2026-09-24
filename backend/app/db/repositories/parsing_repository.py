"""
N-CASA Parsing Repository
"""

from typing import List, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.parsing import ParsedConfigurationModel


def _val(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if hasattr(x, "value"):
        return str(x.value)
    if isinstance(x, bool):
        return default
    return str(x)


class ParsingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_parsed_configs(self, audit_id: str, configs_data: List[Dict[str, Any]]) -> List[ParsedConfigurationModel]:
        await self.session.execute(
            delete(ParsedConfigurationModel).where(ParsedConfigurationModel.audit_id == audit_id)
        )
        models = []
        for item in configs_data:
            model = ParsedConfigurationModel(
                audit_id=audit_id,
                file_id=_val(item.get("file_id")),
                vendor=_val(item.get("vendor"), "UNKNOWN"),
                status=_val(item.get("status"), "UNKNOWN"),
                parsed_data=item.get("parsed_data"),
                evidence=item.get("evidence")
            )
            self.session.add(model)
            models.append(model)
        await self.session.flush()
        return models

    async def get_parsed_configs(self, audit_id: str) -> List[ParsedConfigurationModel]:
        stmt = select(ParsedConfigurationModel).where(ParsedConfigurationModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
