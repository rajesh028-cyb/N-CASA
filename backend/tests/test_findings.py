"""
N-CASA Block 8 Findings Engine Test Suite
============================================
Comprehensive test suite verifying finding creation, deduplication, idempotency,
assessment limitations, query filtering, API endpoints, error handling, and strict scope.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.audit_service import audit_service
from app.compliance.models import (
    AuditComplianceSummary,
    ComplianceEvidence,
    ComplianceResult,
    ComplianceSeverityCounts,
    ComplianceSeverityEnum,
    ComplianceStatusEnum,
    ComplianceSummaryCounts,
)
from app.findings.engine import findings_engine
from app.findings.models import (
    AuditFindingsSummary,
    FindingRecord,
    FindingStatusEnum,
    RemediationStatusEnum,
)

client = TestClient(app)


# ── Sample Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def sample_compliance_summary():
    """Build a deterministic AuditComplianceSummary fixture with PASS, FAIL, NOT_VERIFIABLE results."""
    return AuditComplianceSummary(
        audit_id="AUD-TEST-001",
        status="COMPLIANCE_COMPLETE",
        files_evaluated=2,
        summary=ComplianceSummaryCounts(total_controls=4, passed=1, failed=2, not_verifiable=1),
        severity_counts=ComplianceSeverityCounts(critical=1, high=1, medium=1, low=0),
        results=[
            # 1. FAIL - Critical SSH v2 control
            ComplianceResult(
                control_id="CIS-NET-SSH-001",
                framework="CIS",
                title="Require SSH v2 for Management Access",
                description="Enforce SSH version 2 and disable insecure SSH v1.",
                severity=ComplianceSeverityEnum.CRITICAL,
                category="Management Access",
                status=ComplianceStatusEnum.FAIL,
                expected="SSH v2 must be explicitly enabled.",
                observed="SSH version 1 enabled on VTY lines.",
                explanation="SSH version 1 is active, exposing management sessions.",
                rule="cis_net_ssh_001",
                evidence=[
                    ComplianceEvidence(
                        field="management.ssh.version",
                        value=1,
                        source_file="router_core.cfg",
                        source_line=45,
                        source_text="ip ssh version 1",
                    )
                ],
            ),
            # 2. FAIL - High Telnet control (multi-file for deduplication test)
            ComplianceResult(
                control_id="CIS-NET-TELNET-001",
                framework="CIS",
                title="Disable Telnet Service",
                description="Telnet transmits credentials in plaintext and must be disabled.",
                severity=ComplianceSeverityEnum.HIGH,
                category="Management Access",
                status=ComplianceStatusEnum.FAIL,
                expected="Telnet management service must be disabled.",
                observed="Telnet transport enabled on line vty 0 4.",
                explanation="Plaintext Telnet service is listening.",
                rule="cis_net_telnet_001",
                evidence=[
                    ComplianceEvidence(
                        field="management.telnet.enabled",
                        value=True,
                        source_file="router_core.cfg",
                        source_line=50,
                        source_text="transport input telnet",
                    )
                ],
            ),
            # Multi-file duplicate instance of CIS-NET-TELNET-001
            ComplianceResult(
                control_id="CIS-NET-TELNET-001",
                framework="CIS",
                title="Disable Telnet Service",
                description="Telnet transmits credentials in plaintext and must be disabled.",
                severity=ComplianceSeverityEnum.HIGH,
                category="Management Access",
                status=ComplianceStatusEnum.FAIL,
                expected="Telnet management service must be disabled.",
                observed="Telnet transport enabled on edge interface.",
                explanation="Plaintext Telnet service is listening.",
                rule="cis_net_telnet_001",
                evidence=[
                    ComplianceEvidence(
                        field="management.telnet.enabled",
                        value=True,
                        source_file="switch_edge.cfg",
                        source_line=12,
                        source_text="transport input telnet ssh",
                    )
                ],
            ),
            # 3. PASS - Hostname control (must NOT produce a finding)
            ComplianceResult(
                control_id="CIS-NET-HOST-001",
                framework="CIS",
                title="Require Explicit Device Hostname",
                description="Network devices must have a custom explicit hostname.",
                severity=ComplianceSeverityEnum.LOW,
                category="Management Access",
                status=ComplianceStatusEnum.PASS,
                expected="Custom hostname configured.",
                observed="Hostname set to CORE-RTR-01.",
                explanation="Valid hostname configured.",
                rule="cis_net_host_001",
                evidence=[
                    ComplianceEvidence(
                        field="identity.hostname",
                        value="CORE-RTR-01",
                        source_file="router_core.cfg",
                        source_line=2,
                        source_text="hostname CORE-RTR-01",
                    )
                ],
            ),
            # 4. NOT_VERIFIABLE - NTP control (must NOT produce finding, must produce AssessmentLimitation)
            ComplianceResult(
                control_id="NIST-NET-NTP-001",
                framework="NIST",
                title="Configure Network Time Protocol (NTP)",
                description="Devices must synchronize time using designated NTP servers.",
                severity=ComplianceSeverityEnum.MEDIUM,
                category="Time Synchronization",
                status=ComplianceStatusEnum.NOT_VERIFIABLE,
                expected="NTP servers configured.",
                observed="No NTP server configuration found in inventory file.",
                explanation="Insufficient configuration evidence to verify NTP state.",
                rule="nist_net_ntp_001",
                evidence=[
                    ComplianceEvidence(
                        field="ntp.servers",
                        value=None,
                        source_file="router_core.cfg",
                        source_line=None,
                        source_text="",
                    )
                ],
            ),
        ],
    )


# ── 1. Finding Creation & Extraction Tests ───────────────────────────────────

def test_1_fail_result_creates_finding(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    finding_control_ids = [f.control_id for f in summary.findings]
    assert "CIS-NET-SSH-001" in finding_control_ids
    assert "CIS-NET-TELNET-001" in finding_control_ids


def test_2_pass_result_creates_no_finding(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    finding_control_ids = [f.control_id for f in summary.findings]
    assert "CIS-NET-HOST-001" not in finding_control_ids


def test_3_not_verifiable_creates_no_finding_by_default(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    finding_control_ids = [f.control_id for f in summary.findings]
    assert "NIST-NET-NTP-001" not in finding_control_ids


def test_4_finding_inherits_control_id(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert ssh_finding.control_id == "CIS-NET-SSH-001"


def test_5_finding_inherits_framework(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert ssh_finding.framework == "CIS"


def test_6_finding_inherits_severity(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    telnet_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-TELNET-001")
    assert ssh_finding.severity == "CRITICAL"
    assert telnet_finding.severity == "HIGH"


def test_7_finding_inherits_category(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert ssh_finding.category == "Management Access"


def test_8_finding_preserves_expected_value(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert ssh_finding.expected == "SSH v2 must be explicitly enabled."


def test_9_finding_preserves_observed_value(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert ssh_finding.observed == "SSH version 1 enabled on VTY lines."


def test_10_finding_preserves_evidence(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert len(ssh_finding.evidence) == 1
    assert ssh_finding.evidence[0].source_file == "router_core.cfg"
    assert ssh_finding.evidence[0].source_line == 45
    assert ssh_finding.evidence[0].source_text == "ip ssh version 1"


# ── 2. Deduplication & Idempotency Tests ────────────────────────────────────

def test_11_same_control_produces_one_logical_finding(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    telnet_findings = [f for f in summary.findings if f.control_id == "CIS-NET-TELNET-001"]
    assert len(telnet_findings) == 1


def test_12_multiple_affected_files_aggregate_into_one_finding(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    telnet_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-TELNET-001")
    assert sorted(telnet_finding.affected_files) == ["router_core.cfg", "switch_edge.cfg"]
    assert len(telnet_finding.evidence) == 2


def test_13_re_running_generation_is_idempotent(sample_compliance_summary):
    summary1 = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    summary2 = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    assert len(summary1.findings) == len(summary2.findings)
    assert summary1.findings[0].finding_id == summary2.findings[0].finding_id


def test_14_finding_id_format(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    ssh_finding = next(f for f in summary.findings if f.control_id == "CIS-NET-SSH-001")
    assert ssh_finding.finding_id == "FND-AUD-TEST-001-CIS-NET-SSH-001"


# ── 3. Summary & Assessment Limitations Tests ─────────────────────────────────

def test_15_total_findings_count(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    assert summary.summary.total_findings == 2


def test_16_severity_counts(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    assert summary.summary.critical == 1
    assert summary.summary.high == 1
    assert summary.summary.medium == 0
    assert summary.summary.low == 0


def test_17_open_count(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    assert summary.summary.open == 2
    assert summary.summary.resolved == 0


def test_18_assessment_limitation_count(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    assert summary.summary.assessment_limitations == 1
    assert len(summary.assessment_limitations) == 1
    assert summary.assessment_limitations[0].control_id == "NIST-NET-NTP-001"


# ── 4. Query Filtering Tests ──────────────────────────────────────────────────

def test_19_filter_by_severity(sample_compliance_summary):
    from app.findings.service import findings_service
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    filtered = findings_service.filter_findings(summary, severity="CRITICAL")
    assert len(filtered.findings) == 1
    assert filtered.findings[0].severity == "CRITICAL"


def test_20_filter_by_framework(sample_compliance_summary):
    from app.findings.service import findings_service
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    filtered = findings_service.filter_findings(summary, framework="CIS")
    assert len(filtered.findings) == 2


def test_21_filter_by_status(sample_compliance_summary):
    from app.findings.service import findings_service
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    filtered = findings_service.filter_findings(summary, status="OPEN")
    assert len(filtered.findings) == 2


def test_22_filter_by_category(sample_compliance_summary):
    from app.findings.service import findings_service
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    filtered = findings_service.filter_findings(summary, category="Management Access")
    assert len(filtered.findings) == 2


# ── 5. End-to-End API Routes Tests ───────────────────────────────────────────

def test_23_post_findings_before_compliance_returns_400():
    # Create audit without compliance
    res = client.post(
        "/api/audits",
        files={"file": ("test.cfg", b"hostname router1\n", "text/plain")},
        data={"framework": "CIS"},
    )
    assert res.status_code == 201
    audit_id = res.json()["audit_id"]

    # Attempt findings generation before compliance evaluation
    resp = client.post(f"/api/audits/{audit_id}/findings")
    assert resp.status_code == 400
    assert "Compliance evaluation" in resp.json()["detail"]


def test_24_full_pipeline_ingest_to_findings():
    # 1. Create audit
    config_bytes = b"hostname RTR-CORE-01\nip ssh version 1\nline vty 0 4\n transport input telnet\n"
    res = client.post(
        "/api/audits",
        files={"file": ("cisco_router.cfg", config_bytes, "text/plain")},
        data={"framework": "CIS"},
    )
    assert res.status_code == 201
    audit_id = res.json()["audit_id"]

    # 2. Detect
    res = client.post(f"/api/audits/{audit_id}/detect")
    assert res.status_code == 200

    # 3. Parse
    res = client.post(f"/api/audits/{audit_id}/parse")
    assert res.status_code == 200

    # 4. Normalize
    res = client.post(f"/api/audits/{audit_id}/normalize")
    assert res.status_code == 200

    # 5. Evaluate Compliance
    res = client.post(f"/api/audits/{audit_id}/compliance")
    assert res.status_code == 200

    # 6. Generate Findings (Block 8)
    res = client.post(f"/api/audits/{audit_id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["audit_id"] == audit_id
    assert data["summary"]["total_findings"] >= 1
    assert data["summary"]["assessment_limitations"] >= 0

    # 7. GET /api/audits/{audit_id}/findings
    get_res = client.get(f"/api/audits/{audit_id}/findings")
    assert get_res.status_code == 200
    assert get_res.json()["audit_id"] == audit_id

    # 8. GET /api/audits/{audit_id}/findings/{finding_id}
    finding_id = data["findings"][0]["finding_id"]
    single_res = client.get(f"/api/audits/{audit_id}/findings/{finding_id}")
    assert single_res.status_code == 200
    assert single_res.json()["finding_id"] == finding_id

    # 9. GET /api/findings (global feed)
    global_res = client.get("/api/findings")
    assert global_res.status_code == 200
    assert global_res.json()["summary"]["total_findings"] >= 1


def test_25_missing_audit_returns_404():
    resp = client.get("/api/audits/AUD-NONEXISTENT/findings")
    assert resp.status_code == 404


def test_26_missing_finding_returns_404():
    # Use existing audit
    config_bytes = b"hostname RTR-01\nip ssh version 1\n"
    res = client.post(
        "/api/audits",
        files={"file": ("rtr.cfg", config_bytes, "text/plain")},
        data={"framework": "CIS"},
    )
    audit_id = res.json()["audit_id"]
    client.post(f"/api/audits/{audit_id}/detect")
    client.post(f"/api/audits/{audit_id}/parse")
    client.post(f"/api/audits/{audit_id}/normalize")
    client.post(f"/api/audits/{audit_id}/compliance")
    client.post(f"/api/audits/{audit_id}/findings")

    resp = client.get(f"/api/audits/{audit_id}/findings/FND-FAKE-ID")
    assert resp.status_code == 404


# ── 6. Scope & Non-Inclusion Assertions ──────────────────────────────────────

def test_27_findings_have_pending_block_9_remediation_status(sample_compliance_summary):
    summary = findings_engine.extract_findings("AUD-TEST-001", sample_compliance_summary)
    for f in summary.findings:
        assert f.remediation_status == RemediationStatusEnum.PENDING_BLOCK_9


def test_28_no_ai_or_llm_imports():
    import sys
    assert "openai" not in sys.modules
    assert "langchain" not in sys.modules
    assert "ollama" not in sys.modules
