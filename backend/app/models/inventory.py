"""
N-CASA Configuration Inventory Models (Pydantic)
=================================================
Data transfer objects for configuration file ingestion and discovery.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ConfigStatus(str, Enum):
    """Status of an individual file within an uploaded archive/file."""
    VALID = "VALID"
    SKIPPED = "SKIPPED"
    BINARY = "BINARY"
    EMPTY = "EMPTY"
    ERROR = "ERROR"


class ConfigFileMetadata(BaseModel):
    """Metadata extracted for a single discovered configuration file."""
    file_id: str
    relative_path: str
    file_size: int
    line_count: int = 0
    char_count: int = 0
    non_empty_line_count: int = 0
    comment_line_count: int = 0
    sha256: str
    candidate_hostname: Optional[str] = None
    encoding: str = "utf-8"
    status: ConfigStatus = ConfigStatus.VALID
    skip_reason: Optional[str] = None


class AuditInventory(BaseModel):
    """Complete inventory of discovered configuration files for an audit."""
    audit_id: str
    total_files_discovered: int = 0
    valid_configs_count: int = 0
    skipped_files_count: int = 0
    total_lines: int = 0
    files: list[ConfigFileMetadata] = Field(default_factory=list)
