"""
N-CASA Configuration File Repository
"""

from typing import List, Optional, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.config_file import ConfigFileModel


class ConfigRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_config_files(self, audit_id: str, files_data: List[Dict[str, Any]]) -> List[ConfigFileModel]:
        # Clear previous files for audit if re-running
        await self.session.execute(
            delete(ConfigFileModel).where(ConfigFileModel.audit_id == audit_id)
        )
        models = []
        for file_item in files_data:
            model = ConfigFileModel(
                file_id=file_item["file_id"],
                audit_id=audit_id,
                relative_path=file_item.get("relative_path", "config.cfg"),
                original_filename=file_item.get("original_filename", file_item.get("relative_path", "config.cfg")),
                line_count=file_item.get("line_count", 0),
                char_count=file_item.get("char_count", 0),
                non_empty_line_count=file_item.get("non_empty_line_count", 0),
                comment_line_count=file_item.get("comment_line_count", 0),
                sha256=file_item.get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                candidate_hostname=file_item.get("candidate_hostname"),
                encoding=file_item.get("encoding", "utf-8"),
                status=file_item.get("status", "DISCOVERED")
            )
            self.session.add(model)
            models.append(model)
        await self.session.flush()
        return models

    async def get_config_files(self, audit_id: str) -> List[ConfigFileModel]:
        stmt = select(ConfigFileModel).where(ConfigFileModel.audit_id == audit_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def get_config_file(self, audit_id: str, file_id: str) -> Optional[ConfigFileModel]:
        stmt = select(ConfigFileModel).where(
            ConfigFileModel.audit_id == audit_id,
            ConfigFileModel.file_id == file_id
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()
