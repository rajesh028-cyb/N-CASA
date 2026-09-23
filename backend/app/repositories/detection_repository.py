"""
N-CASA Vendor Detection Repository
"""

from typing import List, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.detection import VendorDetectionModel


def _val(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if hasattr(x, "value"):
        return str(x.value)
    if isinstance(x, bool):
        return default
    return str(x)


class DetectionRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_detections(self, audit_id: str, detections_data: List[Dict[str, Any]]) -> List[VendorDetectionModel]:
        await self.session.execute(
            delete(VendorDetectionModel).where(VendorDetectionModel.audit_id == audit_id)
        )
        models = []
        for item in detections_data:
            model = VendorDetectionModel(
                audit_id=audit_id,
                file_id=_val(item.get("file_id")),
                vendor=_val(item.get("vendor"), "UNKNOWN"),
                device_type=_val(item.get("device_type"), "UNKNOWN"),
                confidence=item.get("confidence", 0.0),
                method=_val(item.get("method"), "DETERMINISTIC"),
                status=_val(item.get("status"), "UNKNOWN"),
                evidence=item.get("evidence")
            )
            self.session.add(model)
            models.append(model)
        await self.session.flush()
        return models

    async def get_detections(self, audit_id: str) -> List[VendorDetectionModel]:
        stmt = select(VendorDetectionModel).where(VendorDetectionModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
