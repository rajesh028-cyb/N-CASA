"""
N-CASA Audit Service — PostgreSQL Persistent Async Implementation
==================================================================
Handles audit business logic, pipeline execution, and database persistence.
PostgreSQL via SQLAlchemy 2.x (asyncpg) is used for persistent storage.
An in-memory cache (_store) is maintained for high performance,
while DB lookup ensures complete data retention across backend restarts.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.db.models import (
    AuditModel,
    ConfigFileModel,
    VendorDetectionModel,
    ParsedConfigurationModel,
    NormalizedConfigurationModel,
    ComplianceResultModel,
    FindingModel,
    AssessmentLimitationModel,
    RemediationModel,
    AIAnalysisResultModel,
    AIExplanationModel,
)
from app.repositories import (
    AuditRepository,
    ConfigRepository,
    DetectionRepository,
    ParsingRepository,
    NormalizationRepository,
    ComplianceRepository,
    FindingRepository,
    RemediationRepository,
    AIRepository,
)

from app.detection import vendor_detector
from app.models.audit import AuditRecord, AuditStatus, Framework
from app.models.detection import (
    AuditDetectionSummary,
    DetectionMethodEnum,
    DetectionStatusEnum,
    DeviceTypeEnum,
    EvidenceItem,
    VendorDetectionResult,
    VendorEnum,
)
from app.compliance import (
    AuditComplianceSummary,
    compliance_engine,
    ComplianceResult,
    ComplianceSeverityEnum,
    ComplianceStatusEnum,
    ComplianceEvidence,
)
from app.findings.service import findings_service
from app.findings.models import (
    AuditFindingsSummary,
    FindingRecord,
    AssessmentLimitation,
    FindingSummaryCounts,
    FindingStatusEnum,
    FindingEvidence,
    RemediationStatusEnum as FindingRemediationStatusEnum,
)
from app.remediation.service import remediation_service
from app.remediation.models import (
    AuditRemediationSummary,
    RemediationRecord,
    RemediationSummaryCounts,
    RemediationStatusEnum,
    ReviewStatusEnum,
)
from app.models.inventory import AuditInventory, ConfigFileMetadata, ConfigStatus
from app.normalization import AuditNormalizationSummary, NormalizationStatusEnum, NormalizedConfiguration, normalizer_registry
from app.parsers import AuditParsingSummary, ParsedConfiguration, ParserStatusEnum, parser_registry
from app.services.ingestion_service import ingestion_service
from app.ai.service import ai_service
from app.ai.models import AIAnalysisSummary, AIExplanationRecord

logger = logging.getLogger("ncasa.audit_service")


def _generate_audit_id() -> str:
    """Generate human-readable public audit ID format: AUD-XXXXXX"""
    return "AUD-" + uuid.uuid4().hex[:6].upper()


def _safe_filename(original: str) -> str:
    """Return a filesystem-safe version of the original filename."""
    base = Path(original).name
    base = base.replace(" ", "_")
    base = "".join(c for c in base if c.isalnum() or c in "._-")
    return base[:200] or "upload"


def _to_enum(enum_cls: type, val: Any, default: Any) -> Any:
    if not val:
        return default
    if isinstance(val, enum_cls):
        return val
    val_str = str(val)
    for member in enum_cls:
        if member.value.upper() == val_str.upper() or member.name.upper() == val_str.upper():
            return member
    return default


def _build_finding_record(df: Any, audit_id: str) -> FindingRecord:
    """Safely convert DB FindingModel or dict into Pydantic FindingRecord."""
    ev_items = []
    if hasattr(df, "evidence") and isinstance(df.evidence, list):
        for ev in df.evidence:
            if isinstance(ev, dict):
                try:
                    ev_items.append(
                        FindingEvidence(
                            field=ev.get("field", "control"),
                            value=ev.get("value"),
                            source_file=ev.get("source_file", ev.get("file_id", "config")),
                            source_line=ev.get("source_line", ev.get("line")),
                            source_text=ev.get("source_text", ev.get("text", "")),
                            reason=ev.get("reason"),
                        )
                    )
                except Exception:
                    pass
    return FindingRecord(
        finding_id=df.finding_id,
        audit_id=audit_id,
        control_id=df.control_id,
        framework=df.framework,
        title=df.title,
        description=df.description,
        severity=df.severity,
        status=_to_enum(FindingStatusEnum, df.status, FindingStatusEnum.OPEN),
        category=df.category or "MANAGEMENT_SECURITY",
        expected=df.expected or "",
        observed=df.observed or "",
        rationale=df.rationale or "",
        remediation_status=_to_enum(FindingRemediationStatusEnum, df.remediation_status, FindingRemediationStatusEnum.PENDING_BLOCK_9),
        affected_files=df.affected_files or [],
        evidence=ev_items,
    )


class AuditService:
    """
    Singleton service class for N-CASA audit management.
    Handles persistence into PostgreSQL via SQLAlchemy 2.x repositories asynchronously.
    """

    def __init__(self) -> None:
        self._store: dict[str, AuditRecord] = {}
        self._lock = threading.Lock()

        # Resolve upload root relative to backend working directory
        self._upload_root = Path(settings.UPLOAD_DIR).resolve()
        self._upload_root.mkdir(parents=True, exist_ok=True)
        logger.info("Upload root initialized: %s", self._upload_root)

    # ── Database Reconstitution ───────────────────────────────────────────────

    async def _load_audit_from_db(self, audit_id: str, session: AsyncSession) -> Optional[AuditRecord]:
        """Reconstruct AuditRecord from PostgreSQL database upon cache miss / backend restart."""
        audit_repo = AuditRepository(session)
        config_repo = ConfigRepository(session)
        det_repo = DetectionRepository(session)
        parse_repo = ParsingRepository(session)
        norm_repo = NormalizationRepository(session)
        comp_repo = ComplianceRepository(session)
        find_repo = FindingRepository(session)
        rem_repo = RemediationRepository(session)
        ai_repo = AIRepository(session)

        audit_model = await audit_repo.get_by_audit_id(audit_id)
        if not audit_model:
            return None

        fw_enum = _to_enum(Framework, audit_model.compliance_framework, Framework.CIS)
        status_enum = _to_enum(AuditStatus, audit_model.status, AuditStatus.UPLOADED)

        record = AuditRecord(
            audit_id=audit_model.audit_id,
            filename=audit_model.original_filename,
            framework=fw_enum,
            status=status_enum,
            file_size=audit_model.file_size,
            created_at=audit_model.created_at,
        )

        # Load Inventory
        if audit_model.inventory:
            try:
                record.inventory = AuditInventory(**audit_model.inventory)
            except Exception:
                pass
        else:
            db_files = await config_repo.get_config_files(audit_id)
            if db_files:
                inv_files = []
                for df in db_files:
                    inv_files.append(
                        ConfigFileMetadata(
                            file_id=df.file_id,
                            relative_path=df.relative_path,
                            original_filename=df.original_filename,
                            line_count=df.line_count,
                            char_count=df.char_count,
                            non_empty_line_count=df.non_empty_line_count,
                            comment_line_count=df.comment_line_count,
                            sha256=df.sha256,
                            candidate_hostname=df.candidate_hostname,
                            encoding=df.encoding,
                            status=_to_enum(ConfigStatus, df.status, ConfigStatus.VALID),
                        )
                    )
                record.inventory = AuditInventory(
                    audit_id=audit_id,
                    total_files_discovered=len(inv_files),
                    valid_configs_count=len(inv_files),
                    total_lines=sum(f.line_count for f in inv_files),
                    files=inv_files,
                )

        # Load Detection Summary
        if audit_model.detection_summary:
            try:
                record.detection_summary = AuditDetectionSummary(**audit_model.detection_summary)
            except Exception:
                pass
        else:
            db_dets = await det_repo.get_detections(audit_id)
            if db_dets:
                det_results = []
                for dd in db_dets:
                    try:
                        ev_list = []
                        if isinstance(dd.evidence, list):
                            for ev in dd.evidence:
                                if isinstance(ev, dict) and "indicator" in ev:
                                    try:
                                        ev_list.append(EvidenceItem(**ev))
                                    except Exception:
                                        pass
                        det_results.append(
                            VendorDetectionResult(
                                file_id=dd.file_id,
                                relative_path=dd.file_id,
                                vendor=_to_enum(VendorEnum, dd.vendor, VendorEnum.UNKNOWN),
                                device_type=_to_enum(DeviceTypeEnum, dd.device_type, DeviceTypeEnum.UNKNOWN),
                                confidence=dd.confidence,
                                method=_to_enum(DetectionMethodEnum, dd.method, DetectionMethodEnum.DETERMINISTIC),
                                status=_to_enum(DetectionStatusEnum, dd.status, DetectionStatusEnum.KNOWN),
                                evidence=ev_list,
                            )
                        )
                    except Exception:
                        pass
                if det_results:
                    record.detection_summary = AuditDetectionSummary(
                        audit_id=audit_id,
                        status="DETECTION_COMPLETE",
                        total_files=len(det_results),
                        detected_files=sum(1 for r in det_results if r.vendor != VendorEnum.UNKNOWN),
                        files=det_results,
                    )
                known_first = next((r for r in det_results if r.vendor != VendorEnum.UNKNOWN), None)
                if known_first:
                    record.vendor = known_first.vendor.value
                    record.device = known_first.device_type.value

        # Load Parsed Configs
        db_parses = await parse_repo.get_parsed_configs(audit_id)
        if db_parses:
            parsed_list = []
            for dp in db_parses:
                try:
                    p_dict = dict(dp.parsed_data) if isinstance(dp.parsed_data, dict) else {}
                    p_dict.setdefault("file_id", dp.file_id)
                    p_dict.setdefault("vendor", dp.vendor or "Cisco")
                    p_dict.setdefault("device_type", "Router")
                    p_dict.setdefault("status", _to_enum(ParserStatusEnum, dp.status, ParserStatusEnum.PARSED))
                    p_dict.setdefault("parser", (dp.vendor or "cisco").lower())
                    if "evidence" in p_dict and isinstance(p_dict["evidence"], dict):
                        p_dict["evidence"] = []
                    parsed_list.append(ParsedConfiguration(**p_dict))
                except Exception:
                    pass
            if parsed_list:
                record.parsing_summary = AuditParsingSummary(
                    audit_id=audit_id,
                    status="PARSING_COMPLETE",
                    total_files=len(parsed_list),
                    parsed_files=sum(1 for p in parsed_list if p.status == ParserStatusEnum.PARSED),
                    files=parsed_list,
                )

        # Load Normalized Configs
        db_norms = await norm_repo.get_normalized_configs(audit_id)
        if db_norms:
            norm_list = []
            for dn in db_norms:
                n_dict = dict(dn.normalized_data) if isinstance(dn.normalized_data, dict) else {}
                n_dict.setdefault("file_id", dn.file_id)
                n_dict.setdefault("vendor", "Cisco")
                n_dict.setdefault("device_type", "Router")
                n_dict.setdefault("normalizer", "cisco")
                n_dict.setdefault("normalization_method", dn.normalization_method or "DETERMINISTIC")
                n_dict.setdefault("status", NormalizationStatusEnum.NORMALIZED)
                try:
                    norm_list.append(NormalizedConfiguration(**n_dict))
                except Exception:
                    norm_list.append(
                        NormalizedConfiguration(
                            file_id=dn.file_id,
                            vendor="Cisco",
                            device_type="Router",
                            normalizer="cisco",
                            normalization_method=dn.normalization_method or "DETERMINISTIC",
                            status=NormalizationStatusEnum.NORMALIZED,
                        )
                    )
            if norm_list:
                record.normalization_summary = AuditNormalizationSummary(
                    audit_id=audit_id,
                    status="NORMALIZATION_COMPLETE",
                    total_files=len(norm_list),
                    normalized_files=len(norm_list),
                    files=norm_list,
                )

        # Load Compliance Results
        db_comps = await comp_repo.get_compliance_results(audit_id)
        if db_comps:
            comp_results = []
            for dc in db_comps:
                try:
                    ev_items = []
                    if isinstance(dc.evidence, list):
                        for ev in dc.evidence:
                            if isinstance(ev, dict):
                                try:
                                    ev_items.append(
                                        ComplianceEvidence(
                                            field=ev.get("field", "control"),
                                            value=ev.get("value"),
                                            source_file=ev.get("source_file", ev.get("file_id", "config")),
                                            source_line=ev.get("source_line", ev.get("line")),
                                            source_text=ev.get("source_text", ev.get("text", "")),
                                        )
                                    )
                                except Exception:
                                    pass
                    comp_results.append(
                        ComplianceResult(
                            control_id=dc.control_id,
                            framework=dc.framework,
                            title=dc.title,
                            severity=_to_enum(ComplianceSeverityEnum, dc.severity, ComplianceSeverityEnum.HIGH),
                            status=_to_enum(ComplianceStatusEnum, dc.status, ComplianceStatusEnum.PASS),
                            expected=dc.expected or "",
                            observed=dc.observed or "",
                            rationale=dc.rationale or "",
                            rule=getattr(dc, "rule", None) or "DETERMINISTIC_RULE",
                            evidence=ev_items,
                        )
                    )
                except Exception as e:
                    print(f"DEBUG COMPLIANCE RECONSTITUTION ERROR: {e}")
                    pass
            if comp_results:
                record.compliance_summary = AuditComplianceSummary(
                    audit_id=audit_id,
                    status="COMPLIANCE_COMPLETE",
                    results=comp_results,
                )

        # Load Findings & Limitations
        db_findings = await find_repo.get_findings(audit_id)
        db_lims = await find_repo.get_limitations(audit_id)
        if db_findings or db_lims:
            f_records = []
            l_records = []
            for df in db_findings:
                try:
                    f_records.append(_build_finding_record(df, audit_id))
                except Exception:
                    pass
            for dl in db_lims:
                try:
                    l_records.append(
                        AssessmentLimitation(
                            control_id=dl.control_id,
                            framework=dl.framework,
                            title=dl.title,
                            description=dl.description,
                            affected_files=dl.affected_files or [],
                            reason=dl.reason,
                        )
                    )
                except Exception:
                    pass
            record.findings_summary = AuditFindingsSummary(
                audit_id=audit_id,
                status="FINDINGS_COMPLETE",
                summary=FindingSummaryCounts(total_findings=len(f_records), assessment_limitations=len(l_records)),
                findings=f_records,
                assessment_limitations=l_records,
            )
            record.findings = len(f_records)

        # Load Remediations
        db_rems = await rem_repo.get_remediations(audit_id)
        if db_rems:
            r_records = []
            for dr in db_rems:
                try:
                    curr_cfg = dr.current_configuration
                    if isinstance(curr_cfg, list):
                        curr_cfg = "\n".join(str(c) for c in curr_cfg)
                    prop_cfg = dr.proposed_configuration
                    if isinstance(prop_cfg, list):
                        prop_cfg = "\n".join(str(c) for c in prop_cfg)
                    roll_guide = dr.rollback_guidance
                    if isinstance(roll_guide, list):
                        roll_guide = "\n".join(str(c) for c in roll_guide)

                    r_records.append(
                        RemediationRecord(
                            remediation_id=dr.remediation_id,
                            finding_id=dr.finding_id,
                            audit_id=audit_id,
                            control_id=dr.control_id,
                            framework=dr.framework,
                            vendor=dr.vendor,
                            device_type=dr.device_type,
                            title=dr.title,
                            description=dr.description,
                            status=_to_enum(RemediationStatusEnum, dr.status, RemediationStatusEnum.AVAILABLE),
                            review_status=_to_enum(ReviewStatusEnum, dr.review_status, ReviewStatusEnum.PENDING_REVIEW),
                            proposed_commands=dr.proposed_commands or [],
                            current_configuration=curr_cfg,
                            proposed_configuration=prop_cfg or "",
                            validation_steps=dr.validation_steps or [],
                            rollback_guidance=roll_guide,
                            affected_files=dr.affected_files or [],
                            evidence=dr.evidence or [],
                            manual_review_required=bool(dr.manual_review_required),
                            required_inputs=dr.required_inputs or [],
                        )
                    )
                except Exception:
                    pass
            if r_records:
                record.remediation_summary = AuditRemediationSummary(
                    audit_id=audit_id,
                    status="REMEDIATION_COMPLETE",
                    summary=RemediationSummaryCounts(remediations_available=len(r_records)),
                    remediations=r_records,
                )

        # Load AI Analysis
        if audit_model.ai_summary:
            try:
                record.ai_analysis_summary = AIAnalysisSummary(**audit_model.ai_summary)
            except Exception:
                pass

        return record

    # ── Public API Implementation ─────────────────────────────────────────────

    async def create_audit(
        self,
        file_bytes: bytes,
        original_filename: str,
        framework: Framework,
        file_size: int,
    ) -> AuditRecord:
        """Validate upload, save file, store PostgreSQL record, and run ingestion."""
        ext = Path(original_filename).suffix.lower()
        if ext not in settings.ALLOWED_EXTENSIONS:
            logger.warning("Rejected upload — invalid extension '%s' for file '%s'", ext, original_filename)
            raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}")

        if file_size > settings.MAX_UPLOAD_BYTES:
            logger.warning("Rejected upload — file '%s' exceeds size limit (%d bytes)", original_filename, file_size)
            raise OverflowError(f"Configuration file exceeds the {settings.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.")

        audit_id = _generate_audit_id()
        safe_name = _safe_filename(original_filename)
        audit_dir = self._upload_root / audit_id
        audit_dir.mkdir(parents=True, exist_ok=True)
        dest_path = audit_dir / safe_name

        await self._write_file(dest_path, file_bytes)

        record = AuditRecord(
            audit_id=audit_id,
            filename=safe_name,
            framework=framework,
            status=AuditStatus.UPLOADED,
            file_size=file_size,
        )

        with self._lock:
            self._store[audit_id] = record

        # Persist to DB
        async with AsyncSessionLocal() as session:
            repo = AuditRepository(session)
            await repo.create_audit(
                audit_id=audit_id,
                status=AuditStatus.UPLOADED.value,
                compliance_framework=framework.value,
                original_filename=safe_name,
                stored_path=str(dest_path),
                file_size=file_size,
            )
            await session.commit()

        logger.info("Audit %s created and persisted | file=%s | framework=%s | size=%d bytes", audit_id, safe_name, framework.value, file_size)

        # Run Ingestion
        await self.ingest_audit(audit_id)

        return await self.get_audit(audit_id) or record

    async def ingest_audit(self, audit_id: str) -> AuditRecord:
        """Run Block 3 Ingestion and persist to DB."""
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        record.status = AuditStatus.INGESTING
        audit_dir = self._upload_root / audit_id
        file_path = audit_dir / record.filename

        try:
            inventory = ingestion_service.process_audit_file(audit_id, file_path, audit_dir)
            with self._lock:
                record.inventory = inventory
                record.status = AuditStatus.READY_FOR_DETECTION

            # DB persistence
            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                config_repo = ConfigRepository(session)
                
                inv_dict = inventory.model_dump() if hasattr(inventory, "model_dump") else dict(inventory)
                await audit_repo.update_inventory(audit_id, inv_dict)
                await audit_repo.update_status(audit_id, AuditStatus.READY_FOR_DETECTION.value)

                files_data = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in inventory.files]
                await config_repo.save_config_files(audit_id, files_data)
                await session.commit()

            logger.info("Audit %s ingestion completed -> READY_FOR_DETECTION (Persisted)", audit_id)
        except Exception as err:
            logger.error("Audit %s ingestion failed: %s", audit_id, err, exc_info=True)
            with self._lock:
                record.status = AuditStatus.FAILED
            raise err

        return record

    async def detect_audit(self, audit_id: str) -> AuditDetectionSummary:
        """Run Block 4 Vendor & Device Detection and persist to DB."""
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        if not record.inventory or not record.inventory.files:
            raise ValueError(f"No configuration inventory found for audit '{audit_id}'. Ingestion required.")

        with self._lock:
            record.status = AuditStatus.DETECTING

        audit_dir = self._upload_root / audit_id
        extracted_dir = audit_dir / "extracted"

        detection_results: list[VendorDetectionResult] = []

        try:
            for cfg_meta in record.inventory.files:
                if cfg_meta.status != ConfigStatus.VALID:
                    detection_results.append(
                        VendorDetectionResult(
                            file_id=cfg_meta.file_id,
                            relative_path=cfg_meta.relative_path,
                            vendor=VendorEnum.UNKNOWN,
                            device_type=DeviceTypeEnum.UNKNOWN,
                            confidence=0.0,
                            method=DetectionMethodEnum.DETERMINISTIC,
                            status=DetectionStatusEnum.UNKNOWN_VENDOR,
                            evidence=[],
                        )
                    )
                    continue

                target_file = extracted_dir / Path(cfg_meta.relative_path)
                if not target_file.exists():
                    target_file = audit_dir / record.filename

                content = ""
                if target_file.exists():
                    try:
                        content = target_file.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        content = target_file.read_text(encoding="latin-1", errors="ignore")

                result = vendor_detector.detect_file(
                    file_id=cfg_meta.file_id,
                    relative_path=cfg_meta.relative_path,
                    content=content,
                )
                detection_results.append(result)

            summary = AuditDetectionSummary(
                audit_id=audit_id,
                status=AuditStatus.DETECTION_COMPLETE.value,
                total_files=len(detection_results),
                detected_files=sum(1 for r in detection_results if r.vendor != VendorEnum.UNKNOWN),
                files=detection_results,
            )

            with self._lock:
                record.detection_summary = summary
                record.status = AuditStatus.DETECTION_COMPLETE
                if detection_results:
                    known_first = next((r for r in detection_results if r.vendor != VendorEnum.UNKNOWN), None)
                    if known_first:
                        record.vendor = known_first.vendor.value
                        record.device = known_first.device_type.value
                    else:
                        record.vendor = VendorEnum.UNKNOWN.value
                        record.device = DeviceTypeEnum.UNKNOWN.value

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                det_repo = DetectionRepository(session)

                sum_dict = summary.model_dump() if hasattr(summary, "model_dump") else dict(summary)
                await audit_repo.update_detection_summary(audit_id, sum_dict)
                await audit_repo.update_status(audit_id, AuditStatus.DETECTION_COMPLETE.value)

                det_data = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in summary.files]
                await det_repo.save_detections(audit_id, det_data)
                await session.commit()

            logger.info("Audit %s detection completed -> %d detected vendor(s) (Persisted)", audit_id, summary.detected_files)
            return summary

        except Exception as err:
            logger.error("Audit %s detection failed: %s", audit_id, err, exc_info=True)
            with self._lock:
                record.status = AuditStatus.DETECTION_FAILED
            raise err

    async def get_audit(self, audit_id: str) -> AuditRecord | None:
        """Retrieve audit record from memory cache or rebuild from PostgreSQL DB on cache miss."""
        with self._lock:
            if audit_id in self._store:
                return self._store[audit_id]

        async with AsyncSessionLocal() as session:
            record = await self._load_audit_from_db(audit_id, session)
            if record:
                with self._lock:
                    self._store[audit_id] = record
            return record

    async def get_inventory(self, audit_id: str) -> AuditInventory | None:
        record = await self.get_audit(audit_id)
        return record.inventory if record else None

    async def get_detection(self, audit_id: str) -> AuditDetectionSummary | None:
        record = await self.get_audit(audit_id)
        return record.detection_summary if record else None

    async def parse_audit(self, audit_id: str) -> AuditParsingSummary:
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        if not record.detection_summary or not record.detection_summary.files:
            raise ValueError(f"No detection results found for audit '{audit_id}'. Run vendor detection first.")

        with self._lock:
            record.status = AuditStatus.PARSING

        audit_dir = self._upload_root / audit_id
        extracted_dir = audit_dir / "extracted"

        parsed_results: list[ParsedConfiguration] = []

        try:
            for det in record.detection_summary.files:
                if det.vendor == VendorEnum.UNKNOWN or det.status == DetectionStatusEnum.UNKNOWN_VENDOR:
                    parsed_results.append(
                        parser_registry.parse_configuration(
                            file_id=det.file_id,
                            vendor=det.vendor.value,
                            device_type=det.device_type.value,
                            content="",
                        )
                    )
                    continue

                target_file = extracted_dir / Path(det.relative_path)
                if not target_file.exists():
                    target_file = audit_dir / record.filename

                content = ""
                if target_file.exists():
                    try:
                        content = target_file.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        content = target_file.read_text(encoding="latin-1", errors="ignore")

                parsed_config = parser_registry.parse_configuration(
                    file_id=det.file_id,
                    vendor=det.vendor.value,
                    device_type=det.device_type.value,
                    content=content,
                )
                parsed_results.append(parsed_config)

            summary = AuditParsingSummary(
                audit_id=audit_id,
                status=AuditStatus.PARSING_COMPLETE.value,
                total_files=len(parsed_results),
                parsed_files=sum(1 for p in parsed_results if p.status == ParserStatusEnum.PARSED),
                unsupported_files=sum(1 for p in parsed_results if p.status == ParserStatusEnum.NOT_PARSED),
                failed_files=sum(1 for p in parsed_results if p.status == ParserStatusEnum.FAILED),
                files=parsed_results,
            )

            with self._lock:
                record.parsing_summary = summary
                record.status = AuditStatus.PARSING_COMPLETE

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                parse_repo = ParsingRepository(session)

                await audit_repo.update_status(audit_id, AuditStatus.PARSING_COMPLETE.value)
                p_data = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in summary.files]
                await parse_repo.save_parsed_configs(audit_id, p_data)
                await session.commit()

            logger.info("Audit %s parsing completed -> %d parsed (Persisted)", audit_id, summary.parsed_files)
            return summary

        except Exception as err:
            logger.error("Audit %s parsing failed: %s", audit_id, err, exc_info=True)
            with self._lock:
                record.status = AuditStatus.PARSING_FAILED
            raise err

    async def get_parsing(self, audit_id: str) -> AuditParsingSummary | None:
        record = await self.get_audit(audit_id)
        return record.parsing_summary if record else None

    async def get_file_parsing(self, audit_id: str, file_id: str) -> ParsedConfiguration | None:
        summary = await self.get_parsing(audit_id)
        if not summary:
            return None
        return next((f for f in summary.files if f.file_id == file_id), None)

    async def normalize_audit(self, audit_id: str) -> AuditNormalizationSummary:
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        if not record.parsing_summary or not record.parsing_summary.files:
            raise ValueError(f"No parsing results found for audit '{audit_id}'. Run vendor parsing first.")

        with self._lock:
            record.status = AuditStatus.NORMALIZING

        normalized_results: list[NormalizedConfiguration] = []

        try:
            for parsed_file in record.parsing_summary.files:
                norm_config = normalizer_registry.normalize_parsed_configuration(parsed_file)
                normalized_results.append(norm_config)

            summary = AuditNormalizationSummary(
                audit_id=audit_id,
                status=AuditStatus.NORMALIZATION_COMPLETE.value,
                total_files=len(normalized_results),
                normalized_files=sum(1 for n in normalized_results if n.status == NormalizationStatusEnum.NORMALIZED),
                partial_files=sum(1 for n in normalized_results if n.status == NormalizationStatusEnum.PARTIAL),
                failed_files=sum(1 for n in normalized_results if n.status == NormalizationStatusEnum.FAILED),
                unsupported_files=sum(1 for n in normalized_results if n.status == NormalizationStatusEnum.NOT_SUPPORTED),
                files=normalized_results,
            )

            with self._lock:
                record.normalization_summary = summary
                record.status = AuditStatus.NORMALIZATION_COMPLETE

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                norm_repo = NormalizationRepository(session)

                await audit_repo.update_status(audit_id, AuditStatus.NORMALIZATION_COMPLETE.value)
                n_data = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in summary.files]
                await norm_repo.save_normalized_configs(audit_id, n_data)
                await session.commit()

            logger.info("Audit %s normalization completed -> %d normalized (Persisted)", audit_id, summary.normalized_files)
            return summary

        except Exception as err:
            logger.error("Audit %s normalization failed: %s", audit_id, err, exc_info=True)
            with self._lock:
                record.status = AuditStatus.NORMALIZATION_FAILED
            raise err

    async def get_normalization(self, audit_id: str) -> AuditNormalizationSummary | None:
        record = await self.get_audit(audit_id)
        return record.normalization_summary if record else None

    async def get_file_normalization(self, audit_id: str, file_id: str) -> NormalizedConfiguration | None:
        summary = await self.get_normalization(audit_id)
        if not summary:
            return None
        return next((f for f in summary.files if f.file_id == file_id), None)

    async def evaluate_compliance(self, audit_id: str, framework: str | None = None) -> AuditComplianceSummary:
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        # Stage Idempotency Guard: Return existing results if stage is already completed
        if record.compliance_summary and record.status == AuditStatus.COMPLIANCE_COMPLETE:
            logger.info("Audit %s compliance evaluation already complete; returning existing results.", audit_id)
            return (await self.get_compliance(audit_id, framework=framework)) or record.compliance_summary

        if not record.normalization_summary or not record.normalization_summary.files:
            raise ValueError(f"No normalization results found for audit '{audit_id}'. Run normalization first.")

        with self._lock:
            record.status = AuditStatus.COMPLIANCE_EVALUATING

        try:
            summary = compliance_engine.evaluate_configurations(
                audit_id=audit_id,
                norm_configs=record.normalization_summary.files,
                framework_filter=framework,
            )

            with self._lock:
                record.compliance_summary = summary
                record.status = AuditStatus.COMPLIANCE_COMPLETE

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                comp_repo = ComplianceRepository(session)

                await audit_repo.update_status(audit_id, AuditStatus.COMPLIANCE_COMPLETE.value)
                c_data = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in summary.results]
                await comp_repo.save_compliance_results(audit_id, c_data)
                await session.commit()

            logger.info("Audit %s compliance evaluation completed -> %d controls evaluated (Persisted)", audit_id, summary.summary.total_controls)
            return summary

        except Exception as err:
            logger.error("Audit %s compliance evaluation failed: %s", audit_id, err, exc_info=True)
            with self._lock:
                record.status = AuditStatus.COMPLIANCE_FAILED
            raise err

    async def get_compliance(self, audit_id: str, framework: str | None = None) -> AuditComplianceSummary | None:
        record = await self.get_audit(audit_id)
        if not record or not record.compliance_summary:
            return None

        summary = record.compliance_summary
        if not framework:
            return summary

        fw_upper = framework.strip().upper()
        filtered_results = [r for r in summary.results if r.framework.upper() == fw_upper]

        return AuditComplianceSummary(
            audit_id=audit_id,
            status=summary.status,
            framework_filter=framework,
            files_evaluated=summary.files_evaluated,
            summary=summary.summary,
            severity_counts=summary.severity_counts,
            results=filtered_results,
        )

    async def get_compliance_control(self, audit_id: str, control_id: str):
        summary = await self.get_compliance(audit_id)
        if not summary:
            return None
        c_id_upper = control_id.strip().upper()
        return next((r for r in summary.results if r.control_id.upper() == c_id_upper), None)

    async def evaluate_findings(self, audit_id: str) -> AuditFindingsSummary:
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        # Stage Idempotency Guard: Return existing summary if stage already completed
        if record.findings_summary and record.status == AuditStatus.FINDINGS_COMPLETE:
            logger.info("Audit %s findings already generated; returning existing summary.", audit_id)
            return record.findings_summary

        if not record.compliance_summary:
            raise ValueError(f"Compliance evaluation (Block 7) has not been performed for audit '{audit_id}'.")

        record.status = AuditStatus.FINDINGS_GENERATING

        try:
            findings_summary = findings_service.generate_findings(
                audit_id=audit_id,
                compliance_summary=record.compliance_summary,
            )
            with self._lock:
                record.findings_summary = findings_summary
                record.findings = findings_summary.summary.total_findings
                record.status = AuditStatus.FINDINGS_COMPLETE

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                find_repo = FindingRepository(session)

                await audit_repo.update_status(audit_id, AuditStatus.FINDINGS_COMPLETE.value)
                f_data = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in findings_summary.findings]
                l_data = [l.model_dump() if hasattr(l, "model_dump") else dict(l) for l in findings_summary.assessment_limitations]
                await find_repo.save_findings(audit_id, f_data, l_data)
                await session.commit()

            logger.info("Audit %s findings generated: %d findings -> FINDINGS_COMPLETE (Persisted)", audit_id, findings_summary.summary.total_findings)
            return findings_summary
        except Exception as err:
            with self._lock:
                record.status = AuditStatus.FINDINGS_FAILED
            logger.error("Audit %s findings generation failed: %s", audit_id, err, exc_info=True)
            raise

    async def get_findings(
        self,
        audit_id: str,
        severity: Optional[str] = None,
        framework: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Optional[AuditFindingsSummary]:
        record = await self.get_audit(audit_id)
        if not record or not record.findings_summary:
            return None

        return findings_service.filter_findings(
            summary=record.findings_summary,
            severity=severity,
            framework=framework,
            status=status,
            category=category,
        )

    async def get_finding(self, audit_id: str, finding_id: str) -> Optional[FindingRecord]:
        summary = await self.get_findings(audit_id)
        if not summary or not summary.findings:
            return None

        f_id_upper = finding_id.strip().upper()
        return next((f for f in summary.findings if f.finding_id.upper() == f_id_upper), None)

    async def evaluate_remediation(self, audit_id: str) -> AuditRemediationSummary:
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        # Stage Idempotency Guard: Return existing summary if stage already completed
        if record.remediation_summary and record.status == AuditStatus.REMEDIATION_COMPLETE:
            logger.info("Audit %s remediation already generated; returning existing summary.", audit_id)
            return record.remediation_summary

        if not record.findings_summary:
            raise ValueError(f"Findings generation (Block 8) has not been performed for audit '{audit_id}'.")

        record.status = AuditStatus.REMEDIATION_GENERATING

        vendor_map = {}
        if record.detection_summary and record.detection_summary.files:
            for df in record.detection_summary.files:
                vendor_map[df.file_id] = df.vendor

        try:
            summary = remediation_service.generate_remediations(
                audit_id=audit_id,
                findings_summary=record.findings_summary,
                vendor_map=vendor_map,
            )
            with self._lock:
                record.remediation_summary = summary
                record.status = AuditStatus.REMEDIATION_COMPLETE

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                rem_repo = RemediationRepository(session)

                await audit_repo.update_status(audit_id, AuditStatus.REMEDIATION_COMPLETE.value)
                r_data = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in summary.remediations]
                await rem_repo.save_remediations(audit_id, r_data)
                await session.commit()

            logger.info("Audit %s remediation generated: %d available -> REMEDIATION_COMPLETE (Persisted)", audit_id, summary.summary.remediations_available)
            return summary
        except Exception as err:
            with self._lock:
                record.status = AuditStatus.REMEDIATION_FAILED
            logger.error("Audit %s remediation generation failed: %s", audit_id, err, exc_info=True)
            raise

    async def get_remediation(
        self,
        audit_id: str,
        vendor: Optional[str] = None,
        status: Optional[str] = None,
        review_status: Optional[str] = None,
    ) -> Optional[AuditRemediationSummary]:
        record = await self.get_audit(audit_id)
        if not record or not record.remediation_summary:
            return None

        return remediation_service.filter_remediations(
            summary=record.remediation_summary,
            vendor=vendor,
            status=status,
            review_status=review_status,
        )

    async def get_remediation_item(self, audit_id: str, remediation_id: str) -> Optional[RemediationRecord]:
        summary = await self.get_remediation(audit_id)
        if not summary or not summary.remediations:
            return None

        rem_id_upper = remediation_id.strip().upper()
        return next((r for r in summary.remediations if r.remediation_id.upper() == rem_id_upper), None)

    async def review_remediation_item(self, audit_id: str, remediation_id: str) -> Optional[RemediationRecord]:
        record = await self.get_audit(audit_id)
        if not record or not record.remediation_summary:
            return None

        updated_record = remediation_service.mark_reviewed(
            summary=record.remediation_summary,
            remediation_id=remediation_id,
        )
        if updated_record:
            async with AsyncSessionLocal() as session:
                rem_repo = RemediationRepository(session)
                r_data = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in record.remediation_summary.remediations]
                await rem_repo.save_remediations(audit_id, r_data)
                await session.commit()
        return updated_record

    async def run_ai_analysis(self, audit_id: str) -> AIAnalysisSummary:
        record = await self.get_audit(audit_id)
        if not record:
            raise KeyError(f"Audit '{audit_id}' not found.")

        if not record.inventory or not record.inventory.files:
            raise ValueError(f"No configuration inventory found for audit '{audit_id}'. Ingestion required.")

        with self._lock:
            record.status = AuditStatus.AI_ANALYZING

        audit_dir = self._upload_root / audit_id
        extracted_dir = audit_dir / "extracted"

        raw_content_map: dict[str, str] = {}
        for cfg in record.inventory.files:
            target_file = extracted_dir / Path(cfg.relative_path)
            if not target_file.exists():
                target_file = audit_dir / record.filename
            if target_file.exists():
                try:
                    raw_content_map[cfg.file_id] = target_file.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    raw_content_map[cfg.file_id] = target_file.read_text(encoding="latin-1", errors="ignore")

        try:
            summary, ai_norm_configs = ai_service.analyze_unknown_configurations(
                audit_id=audit_id,
                inventory_items=record.inventory.files,
                raw_content_map=raw_content_map,
            )

            with self._lock:
                record.ai_analysis_summary = summary
                record.status = AuditStatus.AI_ANALYSIS_COMPLETE

                if ai_norm_configs:
                    if not record.normalization_summary:
                        record.normalization_summary = AuditNormalizationSummary(
                            audit_id=audit_id,
                            status="NORMALIZATION_COMPLETE",
                            total_files=len(ai_norm_configs),
                            normalized_files=len(ai_norm_configs),
                            files=list(ai_norm_configs.values()),
                        )
                    else:
                        existing_ids = {f.file_id for f in record.normalization_summary.files}
                        for file_id, norm_cfg in ai_norm_configs.items():
                            if file_id in existing_ids:
                                record.normalization_summary.files = [
                                    norm_cfg if f.file_id == file_id else f for f in record.normalization_summary.files
                                ]
                            else:
                                record.normalization_summary.files.append(norm_cfg)

            async with AsyncSessionLocal() as session:
                audit_repo = AuditRepository(session)
                ai_repo = AIRepository(session)

                ai_dict = summary.model_dump() if hasattr(summary, "model_dump") else dict(summary)
                await audit_repo.update_ai_summary(audit_id, ai_dict)
                await audit_repo.update_status(audit_id, AuditStatus.AI_ANALYSIS_COMPLETE.value)

                r_data = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in summary.files]
                await ai_repo.save_ai_analysis_results(audit_id, r_data)
                await session.commit()

            logger.info("Audit %s AI analysis completed -> %d file(s) analyzed (Persisted)", audit_id, summary.analyzed_files)
            return summary
        except Exception as err:
            logger.error("Audit %s AI analysis failed: %s", audit_id, err, exc_info=True)
            with self._lock:
                record.status = AuditStatus.FAILED
            raise err

    async def get_finding(self, audit_id: str, finding_id: str) -> Optional[FindingRecord]:
        """Retrieve a specific finding by ID for an audit."""
        audit = await self.get_audit(audit_id)
        if audit and audit.findings_summary and audit.findings_summary.findings:
            for f in audit.findings_summary.findings:
                if f.finding_id == finding_id:
                    return f
        async with AsyncSessionLocal() as session:
            find_repo = FindingRepository(session)
            db_finding = await find_repo.get_finding(audit_id, finding_id)
            if db_finding:
                return _build_finding_record(db_finding, audit_id)
        return None

    async def explain_finding_ai(self, audit_id: str, finding_id: str) -> AIExplanationRecord:
        finding = await self.get_finding(audit_id, finding_id)
        if not finding:
            raise KeyError(f"Finding '{finding_id}' not found in audit '{audit_id}'.")

        record = await self.get_audit(audit_id)
        vendor = record.vendor if record else "UNKNOWN"
        device = record.device if record else "Unknown"

        evidence_lines = finding.evidence if hasattr(finding, "evidence") else []
        if isinstance(evidence_lines, list):
            ev_dicts = [e.model_dump() if hasattr(e, "model_dump") else e for e in evidence_lines]
        else:
            ev_dicts = []

        explanation = ai_service.explain_finding(
            finding=finding.model_dump() if hasattr(finding, "model_dump") else dict(finding),
            evidence_lines=ev_dicts,
            config_snippet=finding.evidence_snippet if hasattr(finding, "evidence_snippet") else "",
            vendor=vendor,
            device_type=device,
        )

        async with AsyncSessionLocal() as session:
            ai_repo = AIRepository(session)
            exp_dict = explanation.model_dump() if hasattr(explanation, "model_dump") else dict(explanation)
            await ai_repo.save_ai_explanation(audit_id, exp_dict)
            await session.commit()

        return explanation

    async def list_audits(self) -> list[AuditRecord]:
        """Return all audits from memory or PostgreSQL database."""
        async with AsyncSessionLocal() as session:
            repo = AuditRepository(session)
            audits, _ = await repo.list_audits(page=1, page_size=100)
            db_records = []
            for a in audits:
                rec = await self._load_audit_from_db(a.audit_id, session)
                if rec:
                    db_records.append(rec)

        with self._lock:
            for r in db_records:
                if r.audit_id not in self._store:
                    self._store[r.audit_id] = r
            all_records = list(self._store.values())

        return sorted(all_records, key=lambda r: r.created_at, reverse=True)

    async def list_audits_paginated(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        framework: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> Tuple[List[AuditRecord], int]:
        """Paginated audit history query directly from PostgreSQL."""
        async with AsyncSessionLocal() as session:
            repo = AuditRepository(session)
            audits, total = await repo.list_audits(
                page=page,
                page_size=page_size,
                status=status,
                framework=framework,
                date_from=date_from,
                date_to=date_to,
            )
            records = []
            for a in audits:
                rec = await self._load_audit_from_db(a.audit_id, session)
                if rec:
                    records.append(rec)
            return records, total

    @staticmethod
    async def _write_file(dest: Path, data: bytes) -> None:
        dest.write_bytes(data)
        logger.debug("Written %d bytes → %s", len(data), dest)


# Global singleton instance
audit_service = AuditService()
