"""
N-CASA Block 12 Test Suite — Reports & Report Generation
=========================================================
Comprehensive unit and integration test coverage for report building, secret redaction,
HTML rendering, PDF generation, path traversal protection, report persistence, and API endpoints.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reports.models import AuditReport, ReportMetadata
from app.reports.builder import ReportBuilder, redact_secrets_text, redact_secrets_obj
from app.reports.html_renderer import HTMLRenderer
from app.reports.pdf_renderer import PDFRenderer
from app.reports.service import ReportService, report_service
from app.db.session import AsyncSessionLocal
from app.repositories import AuditRepository, ComplianceRepository, FindingRepository, ReportRepository
from app.models.audit import AuditRecord, AuditStatus, Framework
from app.compliance import AuditComplianceSummary, ComplianceResult, ComplianceSeverityEnum, ComplianceStatusEnum
from app.services.audit_service import audit_service


client = TestClient(app)


def test_secret_redaction_text():
    """1. Test secret redaction on raw configuration strings."""
    raw_config = "username admin secret 5 $1$ma8$ Password123\nsnmp-server community my_secret_snmp RW"
    redacted = redact_secrets_text(raw_config)
    assert "Password123" not in redacted
    assert "my_secret_snmp" not in redacted
    assert "<REDACTED>" in redacted


def test_secret_redaction_obj():
    """2. Test recursive secret redaction on nested dictionaries."""
    data = {
        "hostname": "R1-CORE",
        "auth": {
            "password": "SuperSecretPassword!",
            "psk": "PreSharedKey123",
            "token": "api_token_abc123",
        },
        "commands": ["enable secret cisco", "show run"],
    }
    redacted = redact_secrets_obj(data)
    assert redacted["auth"]["password"] == "<REDACTED>"
    assert redacted["auth"]["psk"] == "<REDACTED>"
    assert "SuperSecretPassword!" not in str(redacted)
    assert "<REDACTED>" in redacted["commands"][0]


@pytest.mark.asyncio
async def test_report_builder_snapshot():
    """3. Test building an AuditReport snapshot from AuditRecord."""
    audit_id = "AUD-RPT-TEST01"
    async with AsyncSessionLocal() as session:
        audit_repo = AuditRepository(session)
        comp_repo = ComplianceRepository(session)
        find_repo = FindingRepository(session)

        # Clean existing
        existing = await audit_repo.get_by_audit_id(audit_id)
        if existing:
            await session.delete(existing)
            await session.commit()

        # Create audit
        await audit_repo.create_audit(
            audit_id=audit_id,
            status="COMPLIANCE_COMPLETE",
            compliance_framework="CIS",
            original_filename="router.cfg",
            stored_path="/tmp/router.cfg",
            file_size=200,
        )

        # Add compliance result
        await comp_repo.save_compliance_results(audit_id, [{
            "control_id": "CIS-CISCO-1.1",
            "framework": "CIS",
            "title": "Password Encryption",
            "severity": "HIGH",
            "status": "PASS",
            "expected": "service password-encryption",
            "observed": "service password-encryption",
            "rationale": "Encrypted",
        }])

        # Add finding
        await find_repo.save_findings(audit_id, [{
            "finding_id": "FND-CIS-1.2",
            "control_id": "CIS-CISCO-1.2",
            "framework": "CIS",
            "title": "Telnet Enabled",
            "description": "Telnet is enabled",
            "severity": "CRITICAL",
            "status": "FAIL",
            "category": "SECURITY",
            "expected": "transport input ssh",
            "observed": "transport input telnet",
            "rationale": "Insecure",
            "remediation_status": "PENDING_BLOCK_9",
            "affected_files": ["router.cfg"],
            "evidence": [{"line": 42, "text": "transport input telnet"}],
        }], limitations_data=[{
            "control_id": "CIS-CISCO-9.9",
            "framework": "CIS",
            "title": "BGP Auth",
            "description": "BGP absent",
            "affected_files": ["router.cfg"],
            "reason": "Feature not configured",
        }])
        await session.commit()

    # Load audit via service
    rec = await audit_service.get_audit(audit_id)
    assert rec is not None

    # Build snapshot
    report = ReportBuilder.build(rec)
    assert report.audit_id == audit_id
    assert report.report_id.startswith("RPT-AUD-")
    assert report.compliance_summary["pass_count"] >= 1
    assert len(report.findings) == 1
    assert len(report.assessment_limitations) == 1


def test_html_rendering():
    """4. Test rendering AuditReport model into HTML string."""
    report = AuditReport(
        report_id="RPT-TEST-HTML",
        audit_id="AUD-TEST-01",
        audit_metadata={"framework": "CIS", "status": "COMPLIANCE_COMPLETE"},
        inventory_summary={"valid_configs_count": 1},
        compliance_summary={"total_controls": 2, "pass_count": 1, "fail_count": 1},
        compliance_results=[
            {"control_id": "CIS-1.1", "framework": "CIS", "title": "Enc", "severity": "HIGH", "status": "PASS"},
            {"control_id": "CIS-1.2", "framework": "CIS", "title": "Telnet", "severity": "CRITICAL", "status": "FAIL"},
        ],
        findings=[
            {"finding_id": "FND-1.2", "title": "Telnet Enabled", "severity": "CRITICAL", "status": "FAIL", "control_id": "CIS-1.2", "framework": "CIS", "description": "Telnet enabled", "expected": "ssh", "observed": "telnet", "evidence": [{"source_file": "r.cfg", "source_line": 42, "source_text": "transport input telnet"}]},
        ],
        assessment_limitations=[
            {"control_id": "CIS-9.9", "framework": "CIS", "title": "BGP", "reason": "Absent"},
        ],
    )

    renderer = HTMLRenderer()
    html = renderer.render(report)
    assert "N-CASA Automated Security Audit Report" in html
    assert "RPT-TEST-HTML" in html
    assert "FND-1.2" in html
    assert "MANDATORY SAFETY NOTICE" in html.upper()


def test_pdf_rendering():
    """5. Test converting HTML string into PDF binary."""
    html_content = "<html><body><h1>N-CASA Test Report</h1><p>Compliance: PASS</p></body></html>"
    pdf_bytes = PDFRenderer.render_html_to_pdf(html_content)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500


@pytest.mark.asyncio
async def test_report_service_generation_flow():
    """6. Test full ReportService generation flow including file creation and DB persistence."""
    audit_id = "AUD-RPT-FLOW"
    async with AsyncSessionLocal() as session:
        audit_repo = AuditRepository(session)
        comp_repo = ComplianceRepository(session)

        # Clean existing
        existing = await audit_repo.get_by_audit_id(audit_id)
        if existing:
            await session.delete(existing)
            await session.commit()

        await audit_repo.create_audit(
            audit_id=audit_id,
            status="COMPLIANCE_COMPLETE",
            compliance_framework="CIS",
            original_filename="cisco.cfg",
            stored_path="/tmp/cisco.cfg",
            file_size=150,
        )
        await comp_repo.save_compliance_results(audit_id, [{
            "control_id": "CIS-1.1",
            "framework": "CIS",
            "title": "Enable Password Encryption",
            "severity": "HIGH",
            "status": "PASS",
            "expected": "enabled",
            "observed": "enabled",
            "rationale": "Passwords encrypted",
        }])
        await session.commit()

    # Generate Report
    meta = await report_service.generate_report(audit_id)
    assert meta.report_id.startswith("RPT-AUD-")
    assert Path(meta.html_path).exists()
    assert Path(meta.pdf_path).exists()

    # List reports
    reports = await report_service.list_reports(audit_id)
    assert len(reports) >= 1
    assert reports[0].report_id == meta.report_id

    # Get single metadata
    single = await report_service.get_report_metadata(audit_id, meta.report_id)
    assert single is not None
    assert single.report_id == meta.report_id


@pytest.mark.asyncio
async def test_multiple_report_versions():
    """7. Test that generating multiple reports for the same audit creates distinct persistent snapshot records."""
    audit_id = "AUD-RPT-FLOW"
    meta1 = await report_service.generate_report(audit_id)
    meta2 = await report_service.generate_report(audit_id)

    assert meta1.report_id != meta2.report_id
    reports = await report_service.list_reports(audit_id)
    assert len(reports) >= 2


@pytest.mark.asyncio
async def test_path_traversal_protection():
    """8. Test security path traversal validation on report file paths."""
    with pytest.raises(ValueError):
        await report_service.get_report_file_path("../../etc", "RPT-001", "html")


def test_reports_api_flow():
    """9. Test FastAPI endpoints for report generation, listing, HTML view, and PDF download."""
    audit_id = "AUD-RPT-API"
    async def _insert_test_data():
        async with AsyncSessionLocal() as session:
            audit_repo = AuditRepository(session)
            comp_repo = ComplianceRepository(session)

            # Clean existing
            existing = await audit_repo.get_by_audit_id(audit_id)
            if existing:
                await session.delete(existing)
                await session.commit()

            await audit_repo.create_audit(
                audit_id=audit_id,
                status="COMPLIANCE_COMPLETE",
                compliance_framework="CIS",
                original_filename="switch.cfg",
                stored_path="/tmp/switch.cfg",
                file_size=120,
            )
            await comp_repo.save_compliance_results(audit_id, [{
                "control_id": "CIS-1.1",
                "framework": "CIS",
                "title": "Enable Password Encryption",
                "severity": "HIGH",
                "status": "PASS",
                "expected": "enabled",
                "observed": "enabled",
                "rationale": "Passwords encrypted",
            }])
            await session.commit()

    import asyncio
    asyncio.run(_insert_test_data())

    # POST /api/audits/{audit_id}/reports
    res_post = client.post(f"/api/audits/{audit_id}/reports")
    assert res_post.status_code == 201
    data_post = res_post.json()
    report_id = data_post["report_id"]
    assert report_id.startswith("RPT-AUD-")

    # GET /api/audits/{audit_id}/reports
    res_list = client.get(f"/api/audits/{audit_id}/reports")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    # GET /api/audits/{audit_id}/reports/{report_id}
    res_meta = client.get(f"/api/audits/{audit_id}/reports/{report_id}")
    assert res_meta.status_code == 200
    assert res_meta.json()["report_id"] == report_id

    # GET /api/audits/{audit_id}/reports/{report_id}/html
    res_html = client.get(f"/api/audits/{audit_id}/reports/{report_id}/html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "N-CASA Automated Security Audit Report" in res_html.text

    # GET /api/audits/{audit_id}/reports/{report_id}/pdf
    res_pdf = client.get(f"/api/audits/{audit_id}/reports/{report_id}/pdf")
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert res_pdf.content.startswith(b"%PDF")
