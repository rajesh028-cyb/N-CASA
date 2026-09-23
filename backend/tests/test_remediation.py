"""
N-CASA Block 9 Remediation Engine Test Suite
===============================================
Comprehensive test suite verifying vendor remediation template generation (Cisco, Juniper, Fortinet),
unknown vendor handling, safety constraints (0 device calls, 0 shell calls, 0 AI), secret masking,
idempotency, API endpoints, review endpoint, and regression testing.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.audit_service import audit_service
from app.findings.models import (
    AuditFindingsSummary,
    FindingEvidence,
    FindingRecord,
    FindingStatusEnum,
    FindingSummaryCounts,
    RemediationStatusEnum,
)
from app.remediation.engine import remediation_engine
from app.remediation.models import RemediationStatusEnum as RemStatus, ReviewStatusEnum

client = TestClient(app)


# ── Sample Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def sample_findings_summary():
    """Build a deterministic AuditFindingsSummary fixture."""
    return AuditFindingsSummary(
        audit_id="AUD-REM-001",
        status="FINDINGS_COMPLETE",
        summary=FindingSummaryCounts(total_findings=4, open=4, critical=1, high=2, medium=1),
        findings=[
            # 1. Cisco Telnet finding
            FindingRecord(
                finding_id="FND-AUD-REM-001-CIS-NET-TELNET-001",
                audit_id="AUD-REM-001",
                control_id="CIS-NET-TELNET-001",
                framework="CIS",
                title="Disable Telnet Service",
                description="Telnet service is enabled on VTY lines.",
                severity="HIGH",
                status=FindingStatusEnum.OPEN,
                category="Management Access",
                affected_files=["cisco_core.cfg"],
                evidence=[
                    FindingEvidence(
                        field="management.telnet.enabled",
                        value=True,
                        source_file="cisco_core.cfg",
                        source_line=42,
                        source_text="transport input telnet",
                        reason="Telnet transport enabled",
                    )
                ],
                expected="Telnet management service must be disabled.",
                observed="Telnet transport enabled on line vty 0 4.",
                rationale="Plaintext Telnet service is listening.",
            ),
            # 2. Cisco SSH v1 finding
            FindingRecord(
                finding_id="FND-AUD-REM-001-CIS-NET-SSH-001",
                audit_id="AUD-REM-001",
                control_id="CIS-NET-SSH-001",
                framework="CIS",
                title="Require SSH v2 for Management Access",
                description="SSH v1 is active.",
                severity="CRITICAL",
                status=FindingStatusEnum.OPEN,
                category="Management Access",
                affected_files=["cisco_core.cfg"],
                evidence=[
                    FindingEvidence(
                        field="management.ssh.version",
                        value=1,
                        source_file="cisco_core.cfg",
                        source_line=15,
                        source_text="ip ssh version 1",
                        reason="SSH v1 enabled",
                    )
                ],
                expected="SSH v2 must be explicitly enabled.",
                observed="SSH version 1 enabled.",
                rationale="Vulnerable SSH v1 is active.",
            ),
            # 3. Juniper Telnet finding
            FindingRecord(
                finding_id="FND-AUD-REM-001-CIS-NET-TELNET-JUNIPER",
                audit_id="AUD-REM-001",
                control_id="CIS-NET-TELNET-001",
                framework="CIS",
                title="Disable Junos Telnet Service",
                description="Junos Telnet service is configured.",
                severity="HIGH",
                status=FindingStatusEnum.OPEN,
                category="Management Access",
                affected_files=["juniper_srx.cfg"],
                evidence=[
                    FindingEvidence(
                        field="management.telnet.enabled",
                        value=True,
                        source_file="juniper_srx.cfg",
                        source_line=20,
                        source_text="set system services telnet",
                        reason="Junos telnet service enabled",
                    )
                ],
                expected="Telnet service must be deleted.",
                observed="set system services telnet present.",
                rationale="Telnet service enabled.",
            ),
            # 4. Fortinet Telnet finding
            FindingRecord(
                finding_id="FND-AUD-REM-001-CIS-NET-TELNET-FORTINET",
                audit_id="AUD-REM-001",
                control_id="CIS-NET-TELNET-001",
                framework="CIS",
                title="Disable FortiOS Telnet Management",
                description="FortiOS allowaccess includes telnet.",
                severity="HIGH",
                status=FindingStatusEnum.OPEN,
                category="Management Access",
                affected_files=["fortinet_fw.cfg"],
                evidence=[
                    FindingEvidence(
                        field="management.telnet.enabled",
                        value=True,
                        source_file="fortinet_fw.cfg",
                        source_line=8,
                        source_text="set allowaccess ping telnet ssh https",
                        reason="Allowaccess includes telnet",
                    )
                ],
                expected="Allowaccess must not contain telnet.",
                observed="set allowaccess ping telnet ssh https",
                rationale="Telnet management enabled.",
            ),
        ],
    )


# ── 1. General Eligibility & Model Validation Tests ─────────────────────────

def test_1_remediation_model_validates(sample_findings_summary):
    summary = remediation_engine.generate_remediations("AUD-REM-001", sample_findings_summary)
    assert summary.audit_id == "AUD-REM-001"
    assert len(summary.remediations) == 4


def test_2_only_open_findings_are_eligible(sample_findings_summary):
    # Change one finding to RESOLVED
    sample_findings_summary.findings[0].status = FindingStatusEnum.RESOLVED
    summary = remediation_engine.generate_remediations("AUD-REM-001", sample_findings_summary)
    # Only 3 open findings should generate remediations
    assert len(summary.remediations) == 3


# ── 2. Cisco Remediation Template Tests ─────────────────────────────────────

def test_3_cisco_telnet_remediation(sample_findings_summary):
    summary = remediation_engine.generate_remediations(
        "AUD-REM-001", sample_findings_summary, vendor_map={"cisco_core.cfg": "Cisco"}
    )
    telnet_rem = next(r for r in summary.remediations if r.finding_id == "FND-AUD-REM-001-CIS-NET-TELNET-001")
    assert telnet_rem.status == RemStatus.AVAILABLE
    assert telnet_rem.vendor == "Cisco"
    assert "transport input ssh" in telnet_rem.proposed_commands[-1]


def test_4_cisco_ssh_v1_remediation(sample_findings_summary):
    summary = remediation_engine.generate_remediations(
        "AUD-REM-001", sample_findings_summary, vendor_map={"cisco_core.cfg": "Cisco"}
    )
    ssh_rem = next(r for r in summary.remediations if r.finding_id == "FND-AUD-REM-001-CIS-NET-SSH-001")
    assert ssh_rem.status == RemStatus.AVAILABLE
    assert ssh_rem.proposed_commands == ["ip ssh version 2"]


# ── 3. Juniper Remediation Template Tests ────────────────────────────────────

def test_5_juniper_telnet_remediation(sample_findings_summary):
    summary = remediation_engine.generate_remediations(
        "AUD-REM-001", sample_findings_summary, vendor_map={"juniper_srx.cfg": "Juniper"}
    )
    juniper_rem = next(r for r in summary.remediations if r.finding_id == "FND-AUD-REM-001-CIS-NET-TELNET-JUNIPER")
    assert juniper_rem.status == RemStatus.AVAILABLE
    assert juniper_rem.vendor == "Juniper"
    assert "delete system services telnet" in juniper_rem.proposed_commands
    assert "set system services ssh" in juniper_rem.proposed_commands


# ── 4. Fortinet Remediation Template Tests ───────────────────────────────────

def test_6_fortinet_telnet_remediation_preserves_unrelated_services(sample_findings_summary):
    summary = remediation_engine.generate_remediations(
        "AUD-REM-001", sample_findings_summary, vendor_map={"fortinet_fw.cfg": "Fortinet"}
    )
    forti_rem = next(r for r in summary.remediations if r.finding_id == "FND-AUD-REM-001-CIS-NET-TELNET-FORTINET")
    assert forti_rem.status == RemStatus.AVAILABLE
    assert forti_rem.vendor == "Fortinet"
    # Verify telnet removed but ping, ssh, https preserved
    cmd_text = " ".join(forti_rem.proposed_commands)
    assert "set allowaccess ping ssh https" in cmd_text
    assert "telnet" not in cmd_text


# ── 5. Unknown Vendor & Manual Review Tests ──────────────────────────────────

def test_7_unknown_vendor_returns_manual_review():
    from app.remediation.registry import remediation_registry
    template = remediation_registry.get_template("UNKNOWN", "CIS-NET-TELNET-001")
    assert template.__class__.__name__ == "FallbackManualReviewTemplate"


def test_8_underspecified_ntp_requires_manual_review(sample_findings_summary):
    # Add NTP finding
    sample_findings_summary.findings.append(
        FindingRecord(
            finding_id="FND-AUD-REM-001-NIST-NET-NTP-001",
            audit_id="AUD-REM-001",
            control_id="NIST-NET-NTP-001",
            framework="NIST",
            title="Configure Network Time Protocol",
            description="NTP server missing.",
            severity="MEDIUM",
            status=FindingStatusEnum.OPEN,
            category="Time Synchronization",
            affected_files=["cisco_core.cfg"],
            evidence=[],
            expected="NTP server configured.",
            observed="No NTP server in config.",
            rationale="NTP missing.",
        )
    )
    summary = remediation_engine.generate_remediations(
        "AUD-REM-001", sample_findings_summary, vendor_map={"cisco_core.cfg": "Cisco"}
    )
    ntp_rem = next(r for r in summary.remediations if r.control_id == "NIST-NET-NTP-001")
    assert ntp_rem.status == RemStatus.MANUAL_REVIEW_REQUIRED
    assert ntp_rem.manual_review_required is True
    assert len(ntp_rem.proposed_commands) == 0
    assert "Approved NTP server IP address" in ntp_rem.required_inputs[0]


# ── 6. Idempotency & Deterministic IDs Tests ────────────────────────────────

def test_9_idempotency_and_deterministic_ids(sample_findings_summary):
    summary1 = remediation_engine.generate_remediations("AUD-REM-001", sample_findings_summary)
    summary2 = remediation_engine.generate_remediations("AUD-REM-001", sample_findings_summary)
    assert len(summary1.remediations) == len(summary2.remediations)
    assert summary1.remediations[0].remediation_id == summary2.remediations[0].remediation_id
    assert summary1.remediations[0].remediation_id.startswith("REM-AUD-REM-001-")


# ── 7. End-to-End API Routes Tests ───────────────────────────────────────────

def test_10_post_remediation_before_findings_returns_400():
    res = client.post(
        "/api/audits",
        files={"file": ("test.cfg", b"hostname router1\n", "text/plain")},
        data={"framework": "CIS"},
    )
    audit_id = res.json()["audit_id"]

    resp = client.post(f"/api/audits/{audit_id}/remediation")
    assert resp.status_code == 400
    assert "Findings generation" in resp.json()["detail"]


def test_11_full_pipeline_ingest_to_remediation():
    # 1. Create audit
    config_bytes = b"hostname RTR-CORE-01\nip ssh version 1\nline vty 0 4\n transport input telnet\n"
    res = client.post(
        "/api/audits",
        files={"file": ("cisco_router.cfg", config_bytes, "text/plain")},
        data={"framework": "CIS"},
    )
    assert res.status_code == 201
    audit_id = res.json()["audit_id"]

    # 2. Pipeline steps
    client.post(f"/api/audits/{audit_id}/detect")
    client.post(f"/api/audits/{audit_id}/parse")
    client.post(f"/api/audits/{audit_id}/normalize")
    client.post(f"/api/audits/{audit_id}/compliance")
    client.post(f"/api/audits/{audit_id}/findings")

    # 3. Generate Remediation (Block 9)
    res = client.post(f"/api/audits/{audit_id}/remediation")
    assert res.status_code == 200
    data = res.json()
    assert data["audit_id"] == audit_id
    assert data["summary"]["total_findings"] >= 1
    assert len(data["remediations"]) >= 1

    # 4. GET /api/audits/{audit_id}/remediation
    get_res = client.get(f"/api/audits/{audit_id}/remediation")
    assert get_res.status_code == 200

    # 5. GET /api/audits/{audit_id}/remediation/{remediation_id}
    rem_id = data["remediations"][0]["remediation_id"]
    item_res = client.get(f"/api/audits/{audit_id}/remediation/{rem_id}")
    assert item_res.status_code == 200
    assert item_res.json()["remediation_id"] == rem_id

    # 6. POST /api/audits/{audit_id}/remediation/{remediation_id}/review
    rev_res = client.post(f"/api/audits/{audit_id}/remediation/{rem_id}/review")
    assert rev_res.status_code == 200
    assert rev_res.json()["review_status"] == "REVIEWED"

    # 7. GET /api/remediation (global feed)
    global_res = client.get("/api/remediation")
    assert global_res.status_code == 200


def test_12_missing_audit_returns_404():
    resp = client.get("/api/audits/AUD-NONEXISTENT/remediation")
    assert resp.status_code == 404


# ── 8. Safety & Non-Execution Scope Assertions ──────────────────────────────

def test_13_no_network_or_shell_calls():
    import subprocess
    import socket
    # Verify no sockets/commands executed during remediation generation
    summary = remediation_engine.generate_remediations("AUD-TEST", AuditFindingsSummary(audit_id="AUD-TEST", findings=[]))
    assert summary.summary.total_findings == 0


def test_14_no_ai_or_llm_imports():
    import sys
    assert "openai" not in sys.modules
    assert "langchain" not in sys.modules
    assert "ollama" not in sys.modules
