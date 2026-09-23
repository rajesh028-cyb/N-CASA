"""
N-CASA Reports API Endpoints
============================
FastAPI routes for generating, listing, viewing, and downloading security audit reports.
"""

from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse

from app.reports.models import ReportMetadata
from app.reports.service import report_service

logger = logging.getLogger("ncasa.api.reports")

router = APIRouter(prefix="/audits/{audit_id}/reports", tags=["Reports"])


@router.post(
    "",
    response_model=ReportMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new Security Audit Report snapshot",
)
async def generate_report(audit_id: str) -> ReportMetadata:
    """Generate a persistent HTML and PDF security audit report snapshot for an audit."""
    try:
        report_meta = await report_service.generate_report(audit_id)
        return report_meta
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to generate report for audit %s: %s", audit_id, exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Report generation failed: {exc}")


@router.get(
    "",
    response_model=List[ReportMetadata],
    summary="List all generated reports for an audit",
)
async def list_reports(audit_id: str) -> List[ReportMetadata]:
    """Retrieve list of generated report metadata entries for an audit."""
    return await report_service.list_reports(audit_id)


@router.get(
    "/{report_id}",
    response_model=ReportMetadata,
    summary="Retrieve report metadata by ID",
)
async def get_report_metadata(audit_id: str, report_id: str) -> ReportMetadata:
    """Retrieve specific report metadata."""
    meta = await report_service.get_report_metadata(audit_id, report_id)
    if not meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found.")
    return meta


@router.get(
    "/{report_id}/html",
    response_class=HTMLResponse,
    summary="Retrieve HTML security audit report",
)
async def get_report_html(audit_id: str, report_id: str) -> HTMLResponse:
    """Serve the rendered HTML report document."""
    try:
        file_path = await report_service.get_report_file_path(audit_id, report_id, fmt="html")
        html_content = file_path.read_text(encoding="utf-8")
        return HTMLResponse(content=html_content, media_type="text/html")
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/{report_id}/pdf",
    response_class=FileResponse,
    summary="Download PDF security audit report",
)
async def get_report_pdf(audit_id: str, report_id: str) -> FileResponse:
    """Download or view the rendered PDF report file."""
    try:
        file_path = await report_service.get_report_file_path(audit_id, report_id, fmt="pdf")
        filename = f"N-CASA-{report_id}.pdf"
        return FileResponse(
            path=str(file_path),
            media_type="application/pdf",
            filename=filename,
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
