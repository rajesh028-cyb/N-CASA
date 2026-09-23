"""
N-CASA Remediation Repository
"""

from typing import List, Optional, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.remediation import RemediationModel


def _val(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if hasattr(x, "value"):
        return str(x.value)
    if isinstance(x, bool):
        return default
    return str(x)


class RemediationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_remediations(self, audit_id: str, remediations_data: List[Dict[str, Any]]) -> List[RemediationModel]:
        await self.session.execute(
            delete(RemediationModel).where(RemediationModel.audit_id == audit_id)
        )
        deduped: Dict[str, Dict[str, Any]] = {}
        for item in remediations_data:
            rid = _val(item.get("remediation_id"))
            if rid:
                deduped[rid] = item

        models = []
        for rid, item in deduped.items():
            model = RemediationModel(
                remediation_id=rid,
                finding_id=_val(item.get("finding_id")),
                audit_id=audit_id,
                control_id=_val(item.get("control_id")),
                framework=_val(item.get("framework"), "CIS"),
                vendor=_val(item.get("vendor"), "UNKNOWN"),
                device_type=_val(item.get("device_type"), "UNKNOWN"),
                title=_val(item.get("title")),
                description=_val(item.get("description")),
                status=_val(item.get("status"), "PROPOSED"),
                review_status=_val(item.get("review_status"), "PENDING"),
                proposed_commands=item.get("proposed_commands", []),
                current_configuration=item.get("current_configuration", []),
                proposed_configuration=item.get("proposed_configuration", []),
                validation_steps=item.get("validation_steps", []),
                rollback_guidance=item.get("rollback_guidance", []),
                affected_files=item.get("affected_files", []),
                evidence=item.get("evidence", []),
                manual_review_required=item.get("manual_review_required", True),
                required_inputs=item.get("required_inputs", [])
            )
            self.session.add(model)
            models.append(model)
        await self.session.flush()
        return models

    async def get_remediations(self, audit_id: str) -> List[RemediationModel]:
        stmt = select(RemediationModel).where(RemediationModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def get_remediation(self, audit_id: str, remediation_id: str) -> Optional[RemediationModel]:
        stmt = select(RemediationModel).where(
            RemediationModel.audit_id == audit_id,
            RemediationModel.remediation_id == remediation_id
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()
