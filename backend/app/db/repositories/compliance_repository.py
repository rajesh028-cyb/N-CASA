"""
N-CASA Compliance Repository
"""

from typing import List, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.compliance import ComplianceResultModel


def _val(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if hasattr(x, "value"):
        return str(x.value)
    if isinstance(x, bool):
        return default
    return str(x)


class ComplianceRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_compliance_results(self, audit_id: str, results_data: List[Dict[str, Any]]) -> List[ComplianceResultModel]:
        await self.session.execute(
            delete(ComplianceResultModel).where(ComplianceResultModel.audit_id == audit_id)
        )

        if not results_data:
            await self.session.flush()
            return []

        models = []
        for item in results_data:
            cid = _val(item.get("control_id"))
            if not cid:
                continue

            ev = item.get("evidence")
            if hasattr(ev, "model_dump"):
                ev = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in ev]
            elif isinstance(ev, list):
                ev = [e.model_dump() if hasattr(e, "model_dump") else (dict(e) if isinstance(e, dict) else e) for e in ev]

            model = ComplianceResultModel(
                audit_id=audit_id,
                control_id=cid,
                framework=_val(item.get("framework"), "CIS"),
                title=_val(item.get("title")),
                severity=_val(item.get("severity"), "MEDIUM"),
                status=_val(item.get("status"), "NOT_VERIFIABLE"),
                expected=_val(item.get("expected")),
                observed=_val(item.get("observed")),
                rationale=_val(item.get("rationale") or item.get("explanation")),
                internal_mapping=_val(item.get("internal_mapping"), None) if item.get("internal_mapping") is not None and not isinstance(item.get("internal_mapping"), bool) else None,
                file_id=_val(item.get("file_id"), None),
                vendor=_val(item.get("vendor"), None),
                evidence=ev,
            )
            self.session.add(model)
            models.append(model)

        await self.session.flush()
        return await self.get_compliance_results(audit_id)

    async def get_compliance_results(self, audit_id: str) -> List[ComplianceResultModel]:
        stmt = select(ComplianceResultModel).where(ComplianceResultModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
