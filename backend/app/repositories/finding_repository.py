"""
N-CASA Finding Repository
"""

from typing import List, Optional, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.finding import FindingModel, AssessmentLimitationModel


def _val(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if hasattr(x, "value"):
        return str(x.value)
    if isinstance(x, bool):
        return default
    return str(x)


class FindingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_findings(
        self,
        audit_id: str,
        findings_data: List[Dict[str, Any]],
        limitations_data: List[Dict[str, Any]]
    ) -> List[FindingModel]:
        await self.session.execute(
            delete(FindingModel).where(FindingModel.audit_id == audit_id)
        )
        await self.session.execute(
            delete(AssessmentLimitationModel).where(AssessmentLimitationModel.audit_id == audit_id)
        )

        deduped_findings: Dict[str, Dict[str, Any]] = {}
        for item in findings_data:
            fid = _val(item.get("finding_id"))
            if fid:
                deduped_findings[fid] = item

        deduped_lims: Dict[str, Dict[str, Any]] = {}
        for lim in limitations_data:
            cid = _val(lim.get("control_id"))
            if cid:
                deduped_lims[cid] = lim

        finding_models = []
        for fid, item in deduped_findings.items():
            model = FindingModel(
                finding_id=fid,
                audit_id=audit_id,
                control_id=_val(item.get("control_id")),
                framework=_val(item.get("framework"), "CIS"),
                title=_val(item.get("title")),
                description=_val(item.get("description")),
                severity=_val(item.get("severity"), "MEDIUM"),
                status=_val(item.get("status"), "FAIL"),
                category=_val(item.get("category"), "CONFIG_SECURITY"),
                expected=_val(item.get("expected")),
                observed=_val(item.get("observed")),
                rationale=_val(item.get("rationale")),
                remediation_status=_val(item.get("remediation_status"), "NOT_REMEDIATED"),
                affected_files=item.get("affected_files", []),
                evidence=item.get("evidence", [])
            )
            self.session.add(model)
            finding_models.append(model)

        for cid, lim_item in deduped_lims.items():
            lim_model = AssessmentLimitationModel(
                audit_id=audit_id,
                control_id=cid,
                framework=_val(lim_item.get("framework"), "CIS"),
                title=_val(lim_item.get("title")),
                description=_val(lim_item.get("description")),
                affected_files=lim_item.get("affected_files", []),
                reason=_val(lim_item.get("reason"))
            )
            self.session.add(lim_model)

        await self.session.flush()
        return finding_models

    async def get_findings(self, audit_id: str) -> List[FindingModel]:
        stmt = select(FindingModel).where(FindingModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def get_finding(self, audit_id: str, finding_id: str) -> Optional[FindingModel]:
        stmt = select(FindingModel).where(
            FindingModel.audit_id == audit_id,
            FindingModel.finding_id == finding_id
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_limitations(self, audit_id: str) -> List[AssessmentLimitationModel]:
        stmt = select(AssessmentLimitationModel).where(AssessmentLimitationModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update_remediation_status(self, audit_id: str, finding_id: str, status: str) -> Optional[FindingModel]:
        finding = await self.get_finding(audit_id, finding_id)
        if finding:
            finding.remediation_status = _val(status)
            await self.session.flush()
        return finding
