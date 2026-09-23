"""
N-CASA Audit Repository
"""

from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.audit import AuditModel
from app.db.models.config_file import ConfigFileModel


class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_audit(
        self,
        audit_id: str,
        status: str,
        compliance_framework: str,
        original_filename: str,
        stored_path: str,
        file_size: int,
        inventory: Optional[Dict[str, Any]] = None
    ) -> AuditModel:
        audit = AuditModel(
            audit_id=audit_id,
            status=status,
            compliance_framework=compliance_framework,
            original_filename=original_filename,
            stored_path=stored_path,
            file_size=file_size,
            inventory=inventory
        )
        self.session.add(audit)
        await self.session.flush()
        return audit

    async def get_by_audit_id(self, audit_id: str) -> Optional[AuditModel]:
        stmt = select(AuditModel).where(AuditModel.audit_id == audit_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(self, audit_id: str, status: str) -> Optional[AuditModel]:
        audit = await self.get_by_audit_id(audit_id)
        if audit:
            audit.status = status
            audit.updated_at = datetime.now()
            await self.session.flush()
        return audit

    async def update_inventory(self, audit_id: str, inventory: Dict[str, Any]) -> Optional[AuditModel]:
        audit = await self.get_by_audit_id(audit_id)
        if audit:
            audit.inventory = inventory
            audit.updated_at = datetime.now()
            await self.session.flush()
        return audit

    async def update_detection_summary(self, audit_id: str, summary: Dict[str, Any]) -> Optional[AuditModel]:
        audit = await self.get_by_audit_id(audit_id)
        if audit:
            audit.detection_summary = summary
            audit.updated_at = datetime.now()
            await self.session.flush()
        return audit

    async def update_ai_summary(self, audit_id: str, summary: Dict[str, Any]) -> Optional[AuditModel]:
        audit = await self.get_by_audit_id(audit_id)
        if audit:
            audit.ai_summary = summary
            audit.updated_at = datetime.now()
            await self.session.flush()
        return audit

    async def list_audits(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        framework: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None
    ) -> Tuple[List[AuditModel], int]:
        stmt = select(AuditModel)
        count_stmt = select(func.count()).select_from(AuditModel)

        if status:
            stmt = stmt.where(AuditModel.status == status)
            count_stmt = count_stmt.where(AuditModel.status == status)
        if framework:
            stmt = stmt.where(AuditModel.compliance_framework == framework)
            count_stmt = count_stmt.where(AuditModel.compliance_framework == framework)
        if date_from:
            stmt = stmt.where(AuditModel.created_at >= date_from)
            count_stmt = count_stmt.where(AuditModel.created_at >= date_from)
        if date_to:
            stmt = stmt.where(AuditModel.created_at <= date_to)
            count_stmt = count_stmt.where(AuditModel.created_at <= date_to)

        # Count total
        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        # Pagination & Ordering
        offset = (page - 1) * page_size
        stmt = stmt.order_by(AuditModel.created_at.desc()).offset(offset).limit(page_size)

        result = await self.session.execute(stmt)
        audits = list(result.scalars().all())
        return audits, total
