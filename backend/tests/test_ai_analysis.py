"""
N-CASA Block 10 Test Suite — AI-Assisted Unknown-Vendor Configuration Understanding
===================================================================================
Comprehensive test coverage for secret redaction, evidence line cross-checking,
confidence thresholding, no evidence hard rules, mock AI provider parsing,
AI-assisted normalized model synthesis, finding explanations, and API endpoints.
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.ai.models import (
    AIEvidence,
    AIParsedField,
    AIParsedOutput,
    AIAnalysisSummary,
    AIExplanationRecord,
)
from app.ai.validators import redact_secrets, validate_evidence, validate_parsed_field, validate_ai_output
from app.ai.provider import MockAIProvider
from app.ai.service import AIService, ai_service
from app.models.audit import AuditRecord, AuditStatus, Framework
from app.db.session import AsyncSessionLocal
from app.repositories import AuditRepository
from app.models.inventory import AuditInventory, ConfigFileMetadata, ConfigStatus
from app.models.detection import VendorEnum, DeviceTypeEnum
from app.services.audit_service import audit_service


client = TestClient(app)


# ── 1. Secret Redaction Tests ─────────────────────────────────────────────────

def test_secret_redaction():
    raw_config = """
    hostname Router1
    enable secret 5 $1$mERr$hx5rVt7rPNo54.
    username admin password cisco123
    snmp-server community public RW
    crypto isakmp key secretPsk123 address 0.0.0.0
    """
    redacted, count = redact_secrets(raw_config)
    assert count >= 3
    assert "cisco123" not in redacted
    assert "public" not in redacted
    assert "<REDACTED>" in redacted
    assert "hostname Router1" in redacted  # Non-secret lines remain unchanged


# ── 2. Line Evidence Validation & Cross-Check Tests ──────────────────────────

def test_evidence_line_bounds_and_text_matching():
    raw_lines = [
        "set system host-name 'VyOS-GW'",
        "set service ssh port '22'",
        "set service telnet disable",
    ]

    # Valid evidence
    ev_valid = [
        AIEvidence(line_start=1, line_end=1, text="set system host-name 'VyOS-GW'", field="hostname", explanation="Match")
    ]
    res_valid = validate_evidence(raw_lines, ev_valid)
    assert len(res_valid) == 1

    # Out of bounds evidence line
    ev_out_of_bounds = [
        AIEvidence(line_start=10, line_end=12, text="invalid line text", field="hostname", explanation="OutOfBounds")
    ]
    res_oob = validate_evidence(raw_lines, ev_out_of_bounds)
    assert len(res_oob) == 0

    # Line text mismatch
    ev_mismatch = [
        AIEvidence(line_start=1, line_end=1, text="completely random text", field="hostname", explanation="Mismatch")
    ]
    res_mismatch = validate_evidence(raw_lines, ev_mismatch)
    assert len(res_mismatch) == 0


# ── 3. Confidence Thresholding & Hard Rule Tests ─────────────────────────────

def test_hard_rule_no_evidence_no_value():
    raw_lines = ["line 1", "line 2"]

    # Field with value but empty evidence -> must be reset to None
    field = AIParsedField(value="RouterX", confidence=0.9, evidence=[])
    validated = validate_parsed_field(raw_lines, field)
    assert validated.value is None
    assert validated.confidence == 0.0
    assert validated.requires_manual_validation is False


def test_confidence_threshold_requires_manual_validation():
    raw_lines = ["hostname TestNode"]
    ev = [AIEvidence(line_start=1, line_end=1, text="hostname TestNode", field="hostname", explanation="Match")]

    # Low confidence score (< 0.65) -> requires_manual_validation = True
    field_low = AIParsedField(value="TestNode", confidence=0.50, evidence=ev)
    val_low = validate_parsed_field(raw_lines, field_low)
    assert val_low.value == "TestNode"
    assert val_low.requires_manual_validation is True

    # High confidence score (>= 0.65) -> requires_manual_validation = False
    field_high = AIParsedField(value="TestNode", confidence=0.85, evidence=ev)
    val_high = validate_parsed_field(raw_lines, field_high)
    assert val_high.value == "TestNode"
    assert val_high.requires_manual_validation is False


# ── 4. Mock AI Provider Unit Tests ───────────────────────────────────────────

def test_mock_ai_provider_mikrotik_parsing():
    provider = MockAIProvider()
    mikrotik_cfg = """
    # Mikrotik RouterOS 6.48
    /system identity set name="Mikrotik-Edge"
    /ip service set ssh disabled=no port=22
    /ip service set telnet disabled=yes
    /ip service set www disabled=no
    """
    output = provider.analyze_config("file-001", mikrotik_cfg)

    assert output.vendor_hypothesis["name"] == "Mikrotik"
    assert output.device_type["value"] == "Router"
    assert output.identity.hostname.value == "Mikrotik-Edge"
    assert output.management.ssh_enabled.value is True
    assert output.management.telnet_enabled.value is False
    assert output.management.http_enabled.value is True


def test_mock_ai_provider_vyos_parsing():
    provider = MockAIProvider()
    vyos_cfg = """
    /* VyOS Configuration */
    set system host-name 'VyOS-Core'
    set service ssh port '22'
    set system syslog host 192.168.1.50
    """
    output = provider.analyze_config("file-002", vyos_cfg)

    assert output.vendor_hypothesis["name"] == "VyOS"
    assert output.identity.hostname.value == "VyOS-Core"
    assert output.logging_remote_servers.value == ["192.168.1.50"]


# ── 5. AI Service Orchestrator Integration Tests ─────────────────────────────

def test_ai_service_analyze_unknown_configurations():
    service = AIService(provider=MockAIProvider())
    raw_map = {
        "file-unk": "/system identity set name=\"Mikrotik-GW\"\n/ip service set telnet disabled=yes",
    }
    inventory_items = [
        ConfigFileMetadata(
            file_id="file-unk",
            relative_path="mikrotik.cfg",
            file_size=100,
            line_count=2,
            sha256="fake_sha",
            status=ConfigStatus.VALID,
        )
    ]

    summary, ai_norm_configs = service.analyze_unknown_configurations("AUD-TEST10", inventory_items, raw_map)

    assert summary.status == "AI_ANALYSIS_COMPLETE"
    assert summary.analyzed_files == 1
    assert "file-unk" in ai_norm_configs

    norm = ai_norm_configs["file-unk"]
    assert norm.vendor == "MIKROTIK"
    assert norm.normalization_method == "AI_ASSISTED"
    assert norm.identity.hostname == "Mikrotik-GW"
    assert norm.management.telnet.enabled is False


# ── 6. Deterministic Guardrail Test ─────────────────────────────────────────

def test_known_vendors_never_sent_to_ai():
    service = AIService(provider=MockAIProvider())
    raw_map = {
        "file-cisco": "hostname CiscoSwitch\nline vty 0 4\n login",
    }

    # Cisco vendor configuration item
    cisco_item = {"file_id": "file-cisco", "relative_path": "cisco.cfg", "vendor": "CISCO"}

    summary, ai_norm_configs = service.analyze_unknown_configurations("AUD-CISCO", [cisco_item], raw_map)
    assert summary.analyzed_files == 0
    assert len(ai_norm_configs) == 0


# ── 7. AI Endpoints Integration Tests ────────────────────────────────────────

def test_ai_analysis_api_flow(tmp_path):
    # Setup test audit with unknown vendor
    audit_id = "AUD-AI100"
    audit_dir = settings.UPLOAD_DIR + f"/{audit_id}"
    os.makedirs(audit_dir, exist_ok=True)

    cfg_path = os.path.join(audit_dir, "unknown_device.cfg")
    with open(cfg_path, "w") as f:
        f.write("/system identity set name=\"Mikrotik-Router\"\n/ip service set telnet disabled=yes")

    inv = AuditInventory(
        audit_id=audit_id,
        total_files_discovered=1,
        valid_configs_count=1,
        total_lines=2,
        files=[
            ConfigFileMetadata(
                file_id="file-unk-01",
                relative_path="unknown_device.cfg",
                file_size=80,
                line_count=2,
                sha256="fake_sha",
                candidate_hostname="Mikrotik-Router",
                status=ConfigStatus.VALID,
            )
        ],
    )

    rec = AuditRecord(
        audit_id=audit_id,
        filename="unknown_device.cfg",
        framework=Framework.CIS,
        status=AuditStatus.READY_FOR_DETECTION,
        file_size=80,
        inventory=inv,
    )
    async def _insert_test_audit():
        async with AsyncSessionLocal() as session:
            repo = AuditRepository(session)
            existing = await repo.get_by_audit_id(audit_id)
            if existing:
                await session.delete(existing)
                await session.commit()
            await repo.create_audit(
                audit_id=audit_id,
                status=AuditStatus.READY_FOR_DETECTION.value,
                compliance_framework="CIS",
                original_filename="unknown_device.cfg",
                stored_path=str(Path(audit_dir) / "unknown_device.cfg"),
                file_size=80,
            )
            await session.commit()
    import asyncio
    asyncio.run(_insert_test_audit())

    with audit_service._lock:
        audit_service._store[audit_id] = rec

    # Test POST /api/audits/{audit_id}/ai/analyze
    res_post = client.post(f"/api/audits/{audit_id}/ai/analyze")
    assert res_post.status_code == 200
    data_post = res_post.json()
    assert data_post["status"] == "AI_ANALYSIS_COMPLETE"
    assert data_post["analyzed_files"] == 1
    assert data_post["files"][0]["vendor_hypothesis"] == "Mikrotik"

    # Test GET /api/audits/{audit_id}/ai-analysis
    res_get = client.get(f"/api/audits/{audit_id}/ai-analysis")
    assert res_get.status_code == 200
    assert res_get.json()["analyzed_files"] == 1

    # Test GET /api/audits/{audit_id} includes ai_analysis_summary
    res_audit = client.get(f"/api/audits/{audit_id}")
    assert res_audit.status_code == 200
    assert res_audit.json()["ai_analysis_summary"] is not None
