"""
N-CASA Configuration Ingestion & Discovery Service
===================================================
Handles configuration file ingestion, ZIP extraction, file discovery,
text decoding, metadata calculation, line counting, and inventory generation.
"""

from __future__ import annotations

import hashlib
import logging
import re
import zipfile
from pathlib import Path
from typing import Optional

from app.models.inventory import AuditInventory, ConfigFileMetadata, ConfigStatus

logger = logging.getLogger("ncasa.ingestion_service")

# Regex for candidate hostname extraction across multiple network vendors
HOSTNAME_REGEXES = [
    re.compile(r"^\s*hostname\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*sysname\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*set\s+system\s+host-name\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*host-name\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?;?", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*switchname\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*device-name\s+[\"']?([A-Za-z0-9_\-\.]+)[\"']?", re.IGNORECASE | re.MULTILINE),
]

IGNORED_FILE_PATTERNS = {
    "__macosx",
    ".ds_store",
    "thumbs.db",
    ".git",
    ".gitignore",
    ".svn",
}


def _is_ignored_path(relative_path: str) -> bool:
    """Return True if path belongs to OS junk, metadata, or hidden VCS files."""
    parts = relative_path.replace("\\", "/").lower().split("/")
    for part in parts:
        if part in IGNORED_FILE_PATTERNS or part.startswith("._"):
            return True
    return False


def _is_binary_content(raw_bytes: bytes) -> bool:
    """Return True if content contains NULL bytes or high binary concentration."""
    if b"\x00" in raw_bytes[:1024]:
        return True
    return False


def extract_candidate_hostname(text: str) -> Optional[str]:
    """Scan text for common hostname patterns (Cisco, Junos, Huawei, Arista, etc.)."""
    for rx in HOSTNAME_REGEXES:
        match = rx.search(text)
        if match:
            return match.group(1).strip()
    return None


class IngestionService:
    """
    Ingestion engine that parses uploaded configuration files or ZIP archives
    and builds an AuditInventory.
    """

    def process_audit_file(self, audit_id: str, file_path: Path, audit_dir: Path) -> AuditInventory:
        """
        Process uploaded audit file (ZIP archive or single config file)
        and return the generated AuditInventory.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Uploaded file does not exist: {file_path}")

        extracted_files: list[tuple[str, Path]] = []  # list of (relative_path, absolute_file_path)

        # 1. Determine if ZIP archive
        if zipfile.is_zipfile(file_path):
            logger.info("Processing ZIP archive for audit %s: %s", audit_id, file_path.name)
            extracted_dir = audit_dir / "extracted"
            extracted_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(file_path, "r") as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue

                    # Zip-Slip security check
                    member_path = Path(member.filename)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        logger.warning("Zip-Slip attempt detected in file %s, skipping", member.filename)
                        continue

                    rel_str = member.filename
                    if _is_ignored_path(rel_str):
                        continue

                    target_file = extracted_dir / member_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)

                    # Extract file securely
                    with zf.open(member) as src, open(target_file, "wb") as dst:
                        dst.write(src.read())

                    extracted_files.append((rel_str, target_file))
        else:
            logger.info("Processing single config file for audit %s: %s", audit_id, file_path.name)
            extracted_files.append((file_path.name, file_path))

        # 2. Extract metadata per discovered file
        discovered_files: list[ConfigFileMetadata] = []
        file_counter = 1
        total_lines = 0
        valid_count = 0
        skipped_count = 0

        for rel_path, abs_path in extracted_files:
            file_id = f"CFG-{file_counter:03d}"
            file_counter += 1

            raw_bytes = abs_path.read_bytes()
            file_size = len(raw_bytes)
            sha256 = hashlib.sha256(raw_bytes).hexdigest()

            # Check if binary
            if _is_binary_content(raw_bytes):
                skipped_count += 1
                discovered_files.append(
                    ConfigFileMetadata(
                        file_id=file_id,
                        relative_path=rel_path,
                        file_size=file_size,
                        sha256=sha256,
                        status=ConfigStatus.BINARY,
                        skip_reason="Binary content detected",
                    )
                )
                continue

            # Decode text
            encoding = "utf-8"
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = raw_bytes.decode("latin-1")
                    encoding = "latin-1"
                except Exception:
                    skipped_count += 1
                    discovered_files.append(
                        ConfigFileMetadata(
                            file_id=file_id,
                            relative_path=rel_path,
                            file_size=file_size,
                            sha256=sha256,
                            status=ConfigStatus.ERROR,
                            skip_reason="Encoding decode failure",
                        )
                    )
                    continue

            # Normalize line endings
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            lines = text.split("\n")
            line_cnt = len(lines)
            char_cnt = len(text)

            non_empty_cnt = 0
            comment_cnt = 0

            for line in lines:
                sline = line.strip()
                if not sline:
                    continue
                non_empty_cnt += 1
                if sline.startswith("!") or sline.startswith("#") or sline.startswith(";") or sline.startswith("//") or sline.startswith("--"):
                    comment_cnt += 1

            hostname = extract_candidate_hostname(text)

            valid_count += 1
            total_lines += line_cnt

            discovered_files.append(
                ConfigFileMetadata(
                    file_id=file_id,
                    relative_path=rel_path,
                    file_size=file_size,
                    line_count=line_cnt,
                    char_count=char_cnt,
                    non_empty_line_count=non_empty_cnt,
                    comment_line_count=comment_cnt,
                    sha256=sha256,
                    candidate_hostname=hostname,
                    encoding=encoding,
                    status=ConfigStatus.VALID,
                )
            )

        inventory = AuditInventory(
            audit_id=audit_id,
            total_files_discovered=len(discovered_files),
            valid_configs_count=valid_count,
            skipped_files_count=skipped_count,
            total_lines=total_lines,
            files=discovered_files,
        )

        logger.info(
            "Ingestion completed for %s: %d total files, %d valid configs, %d lines",
            audit_id, len(discovered_files), valid_count, total_lines
        )
        return inventory


ingestion_service = IngestionService()
