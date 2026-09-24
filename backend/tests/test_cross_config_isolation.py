"""
N-CASA Regression Test Suite: Multi-Config Compliance & Evidence Isolation
==========================================================================
Verifies that multi-config audit packages (e.g. ZIP bundles containing multiple
vendors: Cisco Secure, Cisco Insecure, Fortinet, Juniper, Unknown) are evaluated
with complete configuration isolation:
1. Zero evidence contamination between different configuration files.
2. PASS results from one configuration never contaminate FAIL/NOT_VERIFIABLE results.
3. Observed explanations remain 100% consistent with the originating configuration.
4. Extracted findings only aggregate evidence from configurations that actually failed.
5. Remediations accurately match device vendor and never default UNKNOWN to Cisco.
"""

import io
import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.compliance.engine import compliance_engine
from app.compliance.models import ComplianceStatusEnum
from app.findings.engine import findings_engine
from app.findings.models import FindingStatusEnum
from app.remediation.engine import remediation_engine
from app.remediation.models import RemediationStatusEnum
from app.normalization.models import (
    NormalizationStatusEnum,
    NormalizedAuthentication,
    NormalizedConfiguration,
    NormalizedEvidenceItem,
    NormalizedIdentity,
    NormalizedLogging,
    NormalizedManagement,
    NormalizedNTP,
    NormalizedSSH,
    NormalizedTelnet,
)

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures: Multi-Vendor Normalized Configurations
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def multi_vendor_configs():
    """Create simulated multi-config normalized structures."""
    cisco_secure = NormalizedConfiguration(
        file_id="CFG-001-SECURE",
        vendor="Cisco",
        device_type="ROUTER",
        status=NormalizationStatusEnum.NORMALIZED,
        normalizer="CiscoNormalizer",
        identity=NormalizedIdentity(hostname="N-CASA-CISCO-SECURE"),
        management=NormalizedManagement(
            ssh=NormalizedSSH(enabled=True, version="2"),
            telnet=NormalizedTelnet(enabled=False),
        ),
        authentication=NormalizedAuthentication(
            aaa_enabled=True,
            enable_secret_present=True,
        ),
        logging=NormalizedLogging(
            enabled=True,
            remote_servers=["10.10.10.10"],
        ),
        ntp=NormalizedNTP(
            enabled=True,
            servers=["10.10.10.20"],
        ),
        evidence=[
            NormalizedEvidenceItem(
                field="authentication.aaa_enabled",
                value=True,
                source_vendor="Cisco",
                source_file="CFG-001-SECURE",
                source_line=11,
                source_text="aaa new-model",
                source="normalizer",
            ),
            NormalizedEvidenceItem(
                field="authentication.enable_secret_present",
                value=True,
                source_vendor="Cisco",
                source_file="CFG-001-SECURE",
                source_line=12,
                source_text="enable secret 9 REDACTED_SECRET",
                source="normalizer",
            ),
            NormalizedEvidenceItem(
                field="logging.remote_servers",
                value="10.10.10.10",
                source_vendor="Cisco",
                source_file="CFG-001-SECURE",
                source_line=18,
                source_text="logging host 10.10.10.10",
                source="normalizer",
            ),
        ],
    )

    cisco_insecure = NormalizedConfiguration(
        file_id="CFG-002-INSECURE",
        vendor="Cisco",
        device_type="ROUTER",
        status=NormalizationStatusEnum.NORMALIZED,
        normalizer="CiscoNormalizer",
        identity=NormalizedIdentity(hostname="N-CASA-CISCO-INSECURE"),
        management=NormalizedManagement(
            ssh=NormalizedSSH(enabled=False, version="1"),
            telnet=NormalizedTelnet(enabled=True),
        ),
        authentication=NormalizedAuthentication(
            aaa_enabled=False,
            enable_secret_present=False,
        ),
        logging=NormalizedLogging(
            enabled=False,
            remote_servers=[],
        ),
        evidence=[
            NormalizedEvidenceItem(
                field="management.telnet.enabled",
                value=True,
                source_vendor="Cisco",
                source_file="CFG-002-INSECURE",
                source_line=13,
                source_text="transport input telnet",
                source="normalizer",
            ),
        ],
    )

    fortinet_fw = NormalizedConfiguration(
        file_id="CFG-003-FORTI",
        vendor="Fortinet",
        device_type="FIREWALL",
        status=NormalizationStatusEnum.NORMALIZED,
        normalizer="FortinetNormalizer",
        identity=NormalizedIdentity(hostname="N-CASA-FORTIGATE"),
        management=NormalizedManagement(
            ssh=NormalizedSSH(enabled=True),
            telnet=NormalizedTelnet(enabled=False),
        ),
        authentication=NormalizedAuthentication(
            aaa_enabled=False,
            enable_secret_present=False,
        ),
        logging=NormalizedLogging(
            enabled=True,
            remote_servers=["10.10.10.10"],
        ),
        evidence=[
            NormalizedEvidenceItem(
                field="logging.remote_servers",
                value="10.10.10.10",
                source_vendor="Fortinet",
                source_file="CFG-003-FORTI",
                source_line=28,
                source_text='set server "10.10.10.10"',
                source="normalizer",
            ),
        ],
    )

    unknown_device = NormalizedConfiguration(
        file_id="CFG-004-UNKNOWN",
        vendor="UNKNOWN",
        device_type="Unknown",
        status=NormalizationStatusEnum.NORMALIZED,
        normalizer="UnknownNormalizer",
        identity=NormalizedIdentity(hostname="UNKNOWN-DEVICE"),
        management=NormalizedManagement(
            ssh=NormalizedSSH(enabled=False),
            telnet=NormalizedTelnet(enabled=True),
        ),
        authentication=NormalizedAuthentication(
            aaa_enabled=False,
            enable_secret_present=False,
        ),
        logging=NormalizedLogging(
            enabled=False,
            remote_servers=[],
        ),
        evidence=[],
    )

    return [cisco_secure, cisco_insecure, fortinet_fw, unknown_device]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Multi-Config Compliance Isolation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_multi_config_evaluation_evidence_isolation(multi_vendor_configs):
    """
    Ensure ComplianceEngine evaluates each configuration independently
    and does not cross-contaminate evidence across configs.
    """
    summary = compliance_engine.evaluate_configurations("AUD-MULTI-001", multi_vendor_configs)

    # 4 normalized configs * 13 controls = 52 evaluation results
    assert len(summary.results) == 52

    # Check Cisco Secure NIST-NET-AUTH-001
    sec_auth = next(
        r for r in summary.results
        if r.file_id == "CFG-001-SECURE" and r.control_id == "NIST-NET-AUTH-001"
    )
    assert sec_auth.status == ComplianceStatusEnum.PASS
    assert sec_auth.vendor == "Cisco"
    assert "aaa_enabled: True" in sec_auth.observed
    assert len(sec_auth.evidence) == 2
    assert all(e.source_file == "CFG-001-SECURE" for e in sec_auth.evidence)

    # Check Cisco Insecure NIST-NET-AUTH-001
    insec_auth = next(
        r for r in summary.results
        if r.file_id == "CFG-002-INSECURE" and r.control_id == "NIST-NET-AUTH-001"
    )
    assert insec_auth.status == ComplianceStatusEnum.FAIL
    assert insec_auth.vendor == "Cisco"
    assert "AAA framework is explicitly disabled" in insec_auth.observed
    # Evidence must NOT contain 'aaa new-model' from CFG-001-SECURE!
    for ev in insec_auth.evidence:
        assert "aaa new-model" not in ev.source_text
        assert ev.source_file != "CFG-001-SECURE"

    # Check Cisco Secure NIST-NET-LOG-001
    sec_log = next(
        r for r in summary.results
        if r.file_id == "CFG-001-SECURE" and r.control_id == "NIST-NET-LOG-001"
    )
    assert sec_log.status == ComplianceStatusEnum.PASS
    assert sec_log.vendor == "Cisco"
    assert "10.10.10.10" in sec_log.observed
    assert len(sec_log.evidence) == 1
    assert sec_log.evidence[0].source_file == "CFG-001-SECURE"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Findings Extraction Isolation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_findings_extraction_evidence_isolation(multi_vendor_configs):
    """
    Ensure FindingsEngine only extracts evidence from configurations that actually failed.
    """
    compliance_summary = compliance_engine.evaluate_configurations("AUD-MULTI-001", multi_vendor_configs)
    findings_summary = findings_engine.extract_findings("AUD-MULTI-001", compliance_summary)

    # Cisco Secure passed NIST-NET-AUTH-001 -> it should NOT be in affected_files for the auth finding
    auth_finding = next(
        (f for f in findings_summary.findings if f.control_id == "NIST-NET-AUTH-001"),
        None
    )
    assert auth_finding is not None
    assert "CFG-001-SECURE" not in auth_finding.affected_files

    # The evidence of auth_finding must NEVER contain 'aaa new-model' from CFG-001-SECURE
    for ev in auth_finding.evidence:
        assert ev.source_file != "CFG-001-SECURE"
        assert "aaa new-model" not in ev.source_text

    # Check Telnet finding
    telnet_finding = next(
        (f for f in findings_summary.findings if f.control_id == "CIS-NET-TELNET-001"),
        None
    )
    assert telnet_finding is not None
    assert "CFG-001-SECURE" not in telnet_finding.affected_files
    assert "CFG-002-INSECURE" in telnet_finding.affected_files


# ─────────────────────────────────────────────────────────────────────────────
# 3. Remediation Vendor Traceability Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_remediation_vendor_traceability_and_no_blind_cisco_default(multi_vendor_configs):
    """
    Ensure RemediationEngine accurately matches the device vendor and NEVER defaults
    an UNKNOWN vendor finding to Cisco.
    """
    compliance_summary = compliance_engine.evaluate_configurations("AUD-MULTI-001", multi_vendor_configs)
    findings_summary = findings_engine.extract_findings("AUD-MULTI-001", compliance_summary)

    vendor_map = {
        "CFG-001-SECURE": "Cisco",
        "CFG-002-INSECURE": "Cisco",
        "CFG-003-FORTI": "Fortinet",
        "CFG-004-UNKNOWN": "UNKNOWN",
    }

    rem_summary = remediation_engine.generate_remediations(
        "AUD-MULTI-001",
        findings_summary,
        vendor_map=vendor_map,
    )

    assert len(rem_summary.remediations) == len(findings_summary.findings)

    # For unknown vendor finding: MUST be MANUAL_REVIEW_REQUIRED and vendor == UNKNOWN
    unknown_finding = next(
        (f for f in findings_summary.findings if f.vendor == "UNKNOWN"),
        None
    )
    if unknown_finding:
        rem_unknown = next(r for r in rem_summary.remediations if r.finding_id == unknown_finding.finding_id)
        assert rem_unknown.vendor == "UNKNOWN"
        assert rem_unknown.status == RemediationStatusEnum.MANUAL_REVIEW_REQUIRED


# ─────────────────────────────────────────────────────────────────────────────
# 4. End-to-End Test with Real N-CASA Manual Test Configs ZIP
# ─────────────────────────────────────────────────────────────────────────────

def test_real_zip_audit_workflow_evidence_integrity(client):
    """
    Test uploading the real multi-vendor test ZIP and verify that the resulting
    compliance results, findings, and remediations have zero cross-config contamination.
    """
    zip_path = os.path.join(os.path.dirname(__file__), "..", "..", "test_data", "N-CASA_Manual_Test_Configs.zip")
    if not os.path.exists(zip_path):
        pytest.skip(f"Test data zip not found at {zip_path}")

    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    # 1. POST /api/audits
    resp = client.post(
        "/api/audits",
        files={"file": ("N-CASA_Manual_Test_Configs.zip", io.BytesIO(zip_bytes), "application/zip")},
        data={"framework": "CIS"},
    )
    assert resp.status_code == 201
    audit_id = resp.json()["audit_id"]

    # 2. Ingest, Detect, Parse, Normalize
    ingest_res = client.post(f"/api/audits/{audit_id}/ingest")
    assert ingest_res.status_code == 200

    detect_res = client.post(f"/api/audits/{audit_id}/detect")
    assert detect_res.status_code == 200

    parse_res = client.post(f"/api/audits/{audit_id}/parse")
    assert parse_res.status_code == 200

    norm_res = client.post(f"/api/audits/{audit_id}/normalize")
    assert norm_res.status_code == 200

    # 3. Compliance
    comp_res = client.post(f"/api/audits/{audit_id}/compliance")
    assert comp_res.status_code == 200
    comp_data = comp_res.json()

    # Verify per-file compliance results exist
    assert len(comp_data["results"]) > 0

    # 4. Findings
    find_res = client.post(f"/api/audits/{audit_id}/findings")
    assert find_res.status_code == 200
    find_data = find_res.json()

    # Verify NO finding has contradictory evidence:
    # E.g., no FAIL finding for AAA has 'aaa new-model' or 'enable secret' in its evidence
    for f in find_data.get("findings", []):
        if "AUTH" in f["control_id"] or "AAA" in f["control_id"]:
            for ev in f.get("evidence", []):
                assert "aaa new-model" not in ev.get("source_text", "").lower()

    # 5. Remediation
    rem_res = client.post(f"/api/audits/{audit_id}/remediation")
    assert rem_res.status_code == 200
    rem_data = rem_res.json()
    assert len(rem_data["remediations"]) > 0

    # 6. Report Generation
    rpt_res = client.post(f"/api/audits/{audit_id}/reports")
    assert rpt_res.status_code == 201
