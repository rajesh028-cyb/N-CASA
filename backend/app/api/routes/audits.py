"""
N-CASA Audit API Routes
=========================
Endpoints:
  POST /api/audits              — Upload a configuration file and create an audit
  GET  /api/audits              — List all uploaded audits
  GET  /api/audits/{audit_id}   — Retrieve a single audit by ID

Block 2: upload + in-memory metadata only.
Block 3: ingestion will be triggered from here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from app.models.audit import (
    AuditCreateResponse,
    AuditDetailResponse,
    AuditListResponse,
    AuditStatus,
    Framework,
)
from app.services.audit_service import audit_service
from app.core.config import settings

logger = logging.getLogger("ncasa.routes.audits")

router = APIRouter(tags=["Audits"])


from app.ai.models import AIAnalysisSummary, AIExplanationRecord
from app.compliance import AuditComplianceSummary, ComplianceResult
from app.findings import AuditFindingsSummary, FindingRecord
from app.remediation import AuditRemediationSummary, RemediationRecord
from app.models.detection import AuditDetectionSummary
from app.models.inventory import AuditInventory
from app.normalization import AuditNormalizationSummary, NormalizedConfiguration
from app.parsers.base import AuditParsingSummary, ParsedConfiguration


# ── POST /api/audits ──────────────────────────────────────────────────────────

@router.post(
    "/audits",
    response_model=AuditCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload configuration and create audit",
    description=(
        "Accepts a network configuration file (ZIP, CFG, CONF, TXT) and a "
        "compliance framework selection. Validates the upload, stores the file "
        "safely, generates an Audit ID, runs ingestion, and returns the audit metadata."
    ),
)
async def create_audit(
    file: UploadFile = File(..., description="Network configuration file (.zip, .cfg, .conf, .txt)"),
    framework: Framework = Form(..., description="Compliance framework (CIS | NIST | STIG | ISO27001)"),
) -> AuditCreateResponse:
    """
    Multipart upload endpoint with automatic configuration ingestion.
    """

    # --- Read file into memory (50 MB limit enforced here) ---
    max_bytes = settings.MAX_UPLOAD_BYTES
    chunk_size = 64 * 1024   # 64 KB chunks
    file_bytes = bytearray()
    bytes_read = 0

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        bytes_read += len(chunk)
        if bytes_read > max_bytes:
            logger.warning(
                "Upload rejected — file '%s' exceeds %d MB limit",
                file.filename, max_bytes // (1024 * 1024),
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Configuration file exceeds the {max_bytes // (1024 * 1024)} MB limit.",
            )
        file_bytes.extend(chunk)

    total_size = len(file_bytes)
    logger.info(
        "Received upload — filename='%s', framework=%s, size=%d bytes",
        file.filename, framework.value, total_size,
    )

    # --- Delegate to service layer ---
    try:
        record = await audit_service.create_audit(
            file_bytes=bytes(file_bytes),
            original_filename=file.filename or "upload",
            framework=framework,
            file_size=total_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except OverflowError as exc:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error creating audit for file '%s'", file.filename)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing the upload.",
        )

    return AuditCreateResponse(
        audit_id=record.audit_id,
        filename=record.filename,
        framework=record.framework,
        status=record.status,
        file_size=record.file_size,
        message="Configuration uploaded and ingested successfully.",
    )


# ── POST /api/audits/{audit_id}/ingest ────────────────────────────────────────

@router.post(
    "/audits/{audit_id}/ingest",
    response_model=AuditDetailResponse,
    summary="Trigger ingestion pipeline",
    description="Manually trigger or re-run the configuration ingestion & discovery pipeline.",
)
async def ingest_audit(audit_id: str) -> AuditDetailResponse:
    try:
        record = await audit_service.ingest_audit(audit_id)
        return _to_detail(record)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to ingest audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion pipeline failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/inventory ──────────────────────────────────────

@router.get(
    "/audits/{audit_id}/inventory",
    response_model=AuditInventory,
    summary="Get configuration inventory",
    description="Returns the discovered configuration files and metadata for an audit.",
)
async def get_audit_inventory(audit_id: str) -> AuditInventory:
    inventory = await audit_service.get_inventory(audit_id)
    if inventory is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Configuration inventory for audit '{audit_id}' is not yet available.",
        )
    return inventory


# ── POST /api/audits/{audit_id}/detect ────────────────────────────────────────

@router.post(
    "/audits/{audit_id}/detect",
    response_model=AuditDetectionSummary,
    summary="Trigger vendor & device detection",
    description="Runs deterministic vendor and device type detection across the audit inventory.",
)
async def detect_audit_vendor(audit_id: str) -> AuditDetectionSummary:
    try:
        summary = await audit_service.detect_audit(audit_id)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to run vendor detection for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vendor detection pipeline failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/detection ──────────────────────────────────────

@router.get(
    "/audits/{audit_id}/detection",
    response_model=AuditDetectionSummary,
    summary="Get vendor detection results",
    description="Returns the detection summary, identified vendors, device types, and evidence for an audit.",
)
async def get_audit_detection(audit_id: str) -> AuditDetectionSummary:
    summary = await audit_service.get_detection(audit_id)
    if summary is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Detection results for audit '{audit_id}' are not yet available.",
        )
    return summary


# ── POST /api/audits/{audit_id}/parse ─────────────────────────────────────────

@router.post(
    "/audits/{audit_id}/parse",
    response_model=AuditParsingSummary,
    summary="Trigger vendor configuration parsing",
    description="Parses configurations for known vendors into structured vendor data with line evidence.",
)
async def parse_audit_configurations(audit_id: str) -> AuditParsingSummary:
    try:
        summary = await audit_service.parse_audit(audit_id)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to run vendor configuration parsing for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Parsing pipeline failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/parsing ────────────────────────────────────────

@router.get(
    "/audits/{audit_id}/parsing",
    response_model=AuditParsingSummary,
    summary="Get configuration parsing summary",
    description="Returns aggregate parsing summary across all inventory files.",
)
async def get_audit_parsing(audit_id: str) -> AuditParsingSummary:
    summary = await audit_service.get_parsing(audit_id)
    if summary is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Parsing results for audit '{audit_id}' are not yet available.",
        )
    return summary


# ── GET /api/audits/{audit_id}/parsing/{file_id} ─────────────────────────────

@router.get(
    "/audits/{audit_id}/parsing/{file_id}",
    response_model=ParsedConfiguration,
    summary="Get parsed configuration for a single file",
    description="Returns detailed parsed configuration data and line evidence for a single file.",
)
async def get_file_parsed_configuration(audit_id: str, file_id: str) -> ParsedConfiguration:
    parsed_config = await audit_service.get_file_parsing(audit_id, file_id)
    if parsed_config is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parsed configuration for file '{file_id}' in audit '{audit_id}' not found.",
        )
    return parsed_config


# ── POST /api/audits/{audit_id}/normalize ─────────────────────────────────────

@router.post(
    "/audits/{audit_id}/normalize",
    response_model=AuditNormalizationSummary,
    summary="Trigger vendor-neutral normalization",
    description="Transforms vendor parsed configurations into a unified vendor-neutral security model.",
)
async def normalize_audit_configurations(audit_id: str) -> AuditNormalizationSummary:
    try:
        summary = await audit_service.normalize_audit(audit_id)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to run vendor-neutral normalization for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Normalization pipeline failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/normalization ──────────────────────────────────

@router.get(
    "/audits/{audit_id}/normalization",
    response_model=AuditNormalizationSummary,
    summary="Get configuration normalization summary",
    description="Returns aggregate normalization summary across all inventory files.",
)
async def get_audit_normalization(audit_id: str) -> AuditNormalizationSummary:
    summary = await audit_service.get_normalization(audit_id)
    if summary is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Normalization results for audit '{audit_id}' are not yet available.",
        )
    return summary


# ── GET /api/audits/{audit_id}/normalization/{file_id} ────────────────────────

@router.get(
    "/audits/{audit_id}/normalization/{file_id}",
    response_model=NormalizedConfiguration,
    summary="Get normalized configuration for a single file",
    description="Returns full vendor-neutral security model and source evidence chain for a single file.",
)
async def get_file_normalized_configuration(audit_id: str, file_id: str) -> NormalizedConfiguration:
    norm_config = await audit_service.get_file_normalization(audit_id, file_id)
    if norm_config is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Normalized configuration for file '{file_id}' in audit '{audit_id}' not found.",
        )
    return norm_config


# ── POST /api/audits/{audit_id}/compliance ─────────────────────────────────────

@router.post(
    "/audits/{audit_id}/compliance",
    response_model=AuditComplianceSummary,
    summary="Trigger deterministic compliance engine",
    description="Evaluates vendor-neutral normalized configurations against rule-based controls.",
)
async def evaluate_audit_compliance(
    audit_id: str,
    framework: str | None = None,
) -> AuditComplianceSummary:
    try:
        summary = await audit_service.evaluate_compliance(audit_id, framework=framework)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to run compliance engine for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance pipeline failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/compliance ──────────────────────────────────────

@router.get(
    "/audits/{audit_id}/compliance",
    response_model=AuditComplianceSummary,
    summary="Get configuration compliance summary",
    description="Returns aggregate compliance evaluation results across controls.",
)
async def get_audit_compliance(
    audit_id: str,
    framework: str | None = None,
) -> AuditComplianceSummary:
    summary = await audit_service.get_compliance(audit_id, framework=framework)
    if summary is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Compliance evaluation results for audit '{audit_id}' are not yet available.",
        )
    return summary


# ── GET /api/audits/{audit_id}/compliance/{control_id} ────────────────────────

@router.get(
    "/audits/{audit_id}/compliance/{control_id}",
    response_model=ComplianceResult,
    summary="Get single compliance control result",
    description="Returns full detailed compliance result and evidence for a specific control ID.",
)
async def get_control_compliance_result(audit_id: str, control_id: str) -> ComplianceResult:
    res = await audit_service.get_compliance_control(audit_id, control_id)
    if res is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Compliance result for control '{control_id}' in audit '{audit_id}' not found.",
        )
    return res


# ── POST /api/audits/{audit_id}/findings ──────────────────────────────────────

@router.post(
    "/audits/{audit_id}/findings",
    response_model=AuditFindingsSummary,
    summary="Generate security findings from compliance results",
    description="Extracts deduplicated security findings and assessment limitations from Block 7 compliance evaluation.",
)
async def generate_audit_findings(audit_id: str) -> AuditFindingsSummary:
    try:
        summary = await audit_service.evaluate_findings(audit_id)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to generate findings for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Findings engine failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/findings ───────────────────────────────────────

@router.get(
    "/audits/{audit_id}/findings",
    response_model=AuditFindingsSummary,
    summary="Get security findings for an audit",
    description="Returns deduplicated findings and assessment limitations with optional filtering.",
)
async def get_audit_findings(
    audit_id: str,
    severity: str | None = None,
    framework: str | None = None,
    status_filter: str | None = None,
    category: str | None = None,
) -> AuditFindingsSummary:
    summary = await audit_service.get_findings(
        audit_id=audit_id,
        severity=severity,
        framework=framework,
        status=status_filter,
        category=category,
    )
    if summary is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Findings for audit '{audit_id}' are not yet available.",
        )
    return summary


# ── GET /api/audits/{audit_id}/findings/{finding_id} ──────────────────────────

@router.get(
    "/audits/{audit_id}/findings/{finding_id}",
    response_model=FindingRecord,
    summary="Get single finding record",
    description="Returns detailed finding record including full evidence chain and metadata.",
)
async def get_finding_record(audit_id: str, finding_id: str) -> FindingRecord:
    finding = await audit_service.get_finding(audit_id, finding_id)
    if finding is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' in audit '{audit_id}' not found.",
        )
    return finding


# ── GET /api/findings ─────────────────────────────────────────────────────────

@router.get(
    "/findings",
    response_model=AuditFindingsSummary,
    summary="Get findings across all audits",
    description="Returns findings summary for the latest completed audit or empty summary if none exist.",
)
async def get_all_findings(
    severity: str | None = None,
    framework: str | None = None,
    status_filter: str | None = None,
    category: str | None = None,
) -> AuditFindingsSummary:
    audits = await audit_service.list_audits()
    for audit in audits:
        if audit.findings_summary:
            summary = await audit_service.get_findings(
                audit_id=audit.audit_id,
                severity=severity,
                framework=framework,
                status=status_filter,
                category=category,
            )
            if summary:
                return summary

    # If no findings exist across any audit yet, return empty structure
    from app.findings.models import FindingSummaryCounts
    return AuditFindingsSummary(
        audit_id="GLOBAL",
        status="FINDINGS_COMPLETE",
        summary=FindingSummaryCounts(),
        findings=[],
        assessment_limitations=[],
    )


# ── POST /api/audits/{audit_id}/remediation ───────────────────────────────────

@router.post(
    "/audits/{audit_id}/remediation",
    response_model=AuditRemediationSummary,
    summary="Generate vendor-specific remediation suggestions",
    description="Generates safe, human-reviewable proposed configuration changes for open security findings.",
)
async def generate_audit_remediation(audit_id: str) -> AuditRemediationSummary:
    try:
        summary = await audit_service.evaluate_remediation(audit_id)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to generate remediation for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation engine failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/remediation ────────────────────────────────────

@router.get(
    "/audits/{audit_id}/remediation",
    response_model=AuditRemediationSummary,
    summary="Get remediation report for an audit",
    description="Returns remediation records and summary metrics with optional filtering.",
)
async def get_audit_remediation(
    audit_id: str,
    vendor: str | None = None,
    status_filter: str | None = None,
    review_status: str | None = None,
) -> AuditRemediationSummary:
    summary = await audit_service.get_remediation(
        audit_id=audit_id,
        vendor=vendor,
        status=status_filter,
        review_status=review_status,
    )
    if summary is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Remediation proposals for audit '{audit_id}' are not yet available.",
        )
    return summary


# ── GET /api/audits/{audit_id}/remediation/{remediation_id} ───────────────────

@router.get(
    "/audits/{audit_id}/remediation/{remediation_id}",
    response_model=RemediationRecord,
    summary="Get single remediation record",
    description="Returns detailed remediation proposal, commands, validation steps, and review status.",
)
async def get_remediation_record(audit_id: str, remediation_id: str) -> RemediationRecord:
    rem = await audit_service.get_remediation_item(audit_id, remediation_id)
    if rem is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation record '{remediation_id}' in audit '{audit_id}' not found.",
        )
    return rem


# ── POST /api/audits/{audit_id}/remediation/{remediation_id}/review ──────────

@router.post(
    "/audits/{audit_id}/remediation/{remediation_id}/review",
    response_model=RemediationRecord,
    summary="Mark remediation proposal as reviewed",
    description="Updates review status of a remediation proposal to REVIEWED. Does NOT execute configuration changes.",
)
async def review_remediation_record(audit_id: str, remediation_id: str) -> RemediationRecord:
    rem = await audit_service.review_remediation_item(audit_id, remediation_id)
    if rem is None:
        record = await audit_service.get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit '{audit_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation record '{remediation_id}' in audit '{audit_id}' not found.",
        )
    return rem


# ── GET /api/remediation ──────────────────────────────────────────────────────

@router.get(
    "/remediation",
    response_model=AuditRemediationSummary,
    summary="Get remediation proposals across all audits",
    description="Returns remediation proposals for the latest completed audit or empty summary if none exist.",
)
async def get_all_remediation(
    vendor: str | None = None,
    status_filter: str | None = None,
    review_status: str | None = None,
) -> AuditRemediationSummary:
    audits = await audit_service.list_audits()
    for audit in audits:
        if audit.remediation_summary:
            summary = await audit_service.get_remediation(
                audit_id=audit.audit_id,
                vendor=vendor,
                status=status_filter,
                review_status=review_status,
            )
            if summary:
                return summary

    from app.remediation.models import RemediationSummaryCounts
    return AuditRemediationSummary(
        audit_id="GLOBAL",
        status="REMEDIATION_COMPLETE",
        summary=RemediationSummaryCounts(),
        remediations=[],
    )


# ── GET /api/audits ───────────────────────────────────────────────────────────

@router.get(
    "/audits",
    response_model=AuditListResponse,
    summary="List all audits",
    description="Returns paginated audits in reverse-chronological order.",
)
async def list_audits(
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    framework: str | None = None,
) -> AuditListResponse:
    records, total = await audit_service.list_audits_paginated(
        page=page,
        page_size=page_size,
        status=status,
        framework=framework,
    )
    items = [_to_detail(r) for r in records]
    return AuditListResponse(items=items, total=total)


# ── GET /api/audits/{audit_id} ────────────────────────────────────────────────

@router.get(
    "/audits/{audit_id}",
    response_model=AuditDetailResponse,
    summary="Get audit by ID",
    description="Returns metadata for a single audit.",
)
async def get_audit(audit_id: str) -> AuditDetailResponse:
    record = await audit_service.get_audit(audit_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit '{audit_id}' not found.",
        )
    return _to_detail(record)


# ── POST /api/audits/{audit_id}/ai/analyze ────────────────────────────────────

@router.post(
    "/audits/{audit_id}/ai/analyze",
    response_model=AIAnalysisSummary,
    summary="Trigger AI analysis for unknown vendors",
    description="Runs AI-assisted configuration understanding on inventory items with unknown vendor status.",
)
async def analyze_audit_unknown_vendor(audit_id: str) -> AIAnalysisSummary:
    try:
        summary = await audit_service.run_ai_analysis(audit_id)
        return summary
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed AI analysis for audit '%s'", audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI analysis pipeline failed: {str(exc)}",
        )


# ── GET /api/audits/{audit_id}/ai-analysis ────────────────────────────────────

@router.get(
    "/audits/{audit_id}/ai-analysis",
    response_model=AIAnalysisSummary,
    summary="Get AI analysis summary for an audit",
    description="Returns aggregate AI configuration understanding report.",
)
async def get_audit_ai_analysis(audit_id: str) -> AIAnalysisSummary:
    record = await audit_service.get_audit(audit_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit '{audit_id}' not found.",
        )
    if not record.ai_analysis_summary:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AI analysis results for audit '{audit_id}' are not available.",
        )
    return record.ai_analysis_summary


# ── POST /api/audits/{audit_id}/ai/explain/{finding_id} ──────────────────────

@router.post(
    "/audits/{audit_id}/ai/explain/{finding_id}",
    response_model=AIExplanationRecord,
    summary="Generate AI explanation for a finding",
    description="Provides an AI-assisted explanation of security impact, evidence, and manual review steps for a finding.",
)
async def explain_finding_ai(audit_id: str, finding_id: str) -> AIExplanationRecord:
    try:
        explanation = await audit_service.explain_finding_ai(audit_id, finding_id)
        return explanation
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed AI explanation for finding '%s' in audit '%s'", finding_id, audit_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI explanation failed: {str(exc)}",
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_detail(record) -> AuditDetailResponse:
    return AuditDetailResponse(
        audit_id=record.audit_id,
        filename=record.filename,
        framework=record.framework,
        status=record.status,
        created_at=record.created_at,
        file_size=record.file_size,
        inventory=record.inventory,
        detection_summary=record.detection_summary,
        parsing_summary=record.parsing_summary,
        normalization_summary=record.normalization_summary,
        compliance_summary=record.compliance_summary,
        findings_summary=record.findings_summary,
        remediation_summary=record.remediation_summary,
        ai_analysis_summary=record.ai_analysis_summary,
        vendor=record.vendor,
        device=record.device,
        findings=record.findings,
    )

