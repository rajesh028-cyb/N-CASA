"""
N-CASA Block 11 — PostgreSQL Persistence & Database Integration Tests
=======================================================================
Tests all SQLAlchemy 2.x ORM models, repositories, database constraints,
restart persistence, transactions, and paginated audit history.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.session import AsyncSessionLocal, engine
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
from app.services.audit_service import AuditService, audit_service
from app.models.audit import Framework, AuditStatus


@pytest.mark.asyncio
async def test_db_connection():
    """1. Test direct database connection and ping."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1


@pytest.mark.asyncio
async def test_audit_creation():
    """2. Test creating an audit record in the database."""
    async with AsyncSessionLocal() as session:
        await session.execute(text("DELETE FROM audits WHERE audit_id LIKE 'AUD-DBTEST-%'"))
        await session.commit()

        repo = AuditRepository(session)
        audit_id = "AUD-DBTEST-01"
        audit = await repo.create_audit(
            audit_id=audit_id,
            status="UPLOADED",
            compliance_framework="CIS",
            original_filename="router.cfg",
            stored_path="/storage/uploads/AUD-DBTEST-01/router.cfg",
            file_size=1024,
        )
        await session.commit()
        assert audit.id is not None
        assert audit.audit_id == audit_id


@pytest.mark.asyncio
async def test_audit_retrieval():
    """3. Test retrieving an audit record by public audit_id."""
    async with AsyncSessionLocal() as session:
        repo = AuditRepository(session)
        audit_id = "AUD-DBTEST-01"
        fetched = await repo.get_by_audit_id(audit_id)
        assert fetched is not None
        assert fetched.audit_id == audit_id
        assert fetched.original_filename == "router.cfg"


@pytest.mark.asyncio
async def test_audit_update():
    """4. Test updating audit status and inventory in DB."""
    async with AsyncSessionLocal() as session:
        repo = AuditRepository(session)
        audit_id = "AUD-DBTEST-01"
        updated = await repo.update_status(audit_id, "INGESTING")
        assert updated is not None
        assert updated.status == "INGESTING"

        inv_data = {
            "audit_id": audit_id,
            "total_files_discovered": 1,
            "valid_configs_count": 1,
            "skipped_files_count": 0,
            "total_lines": 150,
            "files": [
                {
                    "file_id": "cfg_001",
                    "relative_path": "router.cfg",
                    "file_size": 3400,
                    "line_count": 150,
                    "char_count": 3400,
                    "non_empty_line_count": 120,
                    "comment_line_count": 30,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "candidate_hostname": "R1-CORE",
                    "encoding": "utf-8",
                    "status": "VALID",
                }
            ],
        }
        updated_inv = await repo.update_inventory(audit_id, inv_data)
        await session.commit()
        assert updated_inv.inventory["total_files_discovered"] == 1


@pytest.mark.asyncio
async def test_config_file_persistence():
    """5. Test config file metadata persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        config_repo = ConfigRepository(session)
        files = [
            {
                "file_id": "cfg_001",
                "relative_path": "router.cfg",
                "original_filename": "router.cfg",
                "line_count": 150,
                "char_count": 3400,
                "non_empty_line_count": 120,
                "comment_line_count": 30,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "candidate_hostname": "R1-CORE",
                "encoding": "utf-8",
                "status": "VALID",
            }
        ]
        saved = await config_repo.save_config_files(audit_id, files)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].candidate_hostname == "R1-CORE"

        fetched_files = await config_repo.get_config_files(audit_id)
        assert len(fetched_files) == 1
        assert fetched_files[0].file_id == "cfg_001"


@pytest.mark.asyncio
async def test_detection_persistence():
    """6. Test vendor detection result persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        det_repo = DetectionRepository(session)
        detections = [
            {
                "file_id": "cfg_001",
                "vendor": "CISCO",
                "device_type": "ROUTER",
                "confidence": 0.95,
                "method": "DETERMINISTIC",
                "status": "KNOWN_VENDOR",
                "evidence": [{"line": 1, "text": "cisco IOS", "category": "HEADER"}],
            }
        ]
        saved = await det_repo.save_detections(audit_id, detections)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].vendor == "CISCO"

        fetched = await det_repo.get_detections(audit_id)
        assert len(fetched) == 1
        assert fetched[0].device_type == "ROUTER"


@pytest.mark.asyncio
async def test_parsing_persistence():
    """7. Test vendor parsed configuration persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        parse_repo = ParsingRepository(session)
        configs = [
            {
                "file_id": "cfg_001",
                "vendor": "CISCO",
                "status": "PARSED",
                "parsed_data": {"hostname": "R1-CORE", "services": {"password_encryption": True}},
                "evidence": {"hostname": {"line": 2, "text": "hostname R1-CORE"}},
            }
        ]
        saved = await parse_repo.save_parsed_configs(audit_id, configs)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].parsed_data["hostname"] == "R1-CORE"


@pytest.mark.asyncio
async def test_normalization_persistence():
    """8. Test vendor-neutral normalized configuration persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        norm_repo = NormalizationRepository(session)
        configs = [
            {
                "file_id": "cfg_001",
                "normalization_method": "DETERMINISTIC",
                "requires_manual_validation": False,
                "confidence": 1.0,
                "normalized_data": {
                    "identity": {"hostname": {"value": "R1-CORE"}},
                    "authentication": {"password_encryption": {"value": True}},
                },
            }
        ]
        saved = await norm_repo.save_normalized_configs(audit_id, configs)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].normalization_method == "DETERMINISTIC"


@pytest.mark.asyncio
async def test_compliance_persistence():
    """9. Test compliance evaluation result persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        comp_repo = ComplianceRepository(session)
        results = [
            {
                "control_id": "CIS-CISCO-1.1",
                "framework": "CIS",
                "title": "Enable Password Encryption",
                "severity": "HIGH",
                "status": "PASS",
                "expected": "service password-encryption enabled",
                "observed": "service password-encryption is active",
                "rationale": "Passwords encrypted",
                "internal_mapping": "AUTH_01",
                "evidence": [{"file_id": "cfg_001", "line": 5, "text": "service password-encryption"}],
            }
        ]
        saved = await comp_repo.save_compliance_results(audit_id, results)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].control_id == "CIS-CISCO-1.1"


@pytest.mark.asyncio
async def test_finding_persistence():
    """10. Test finding & limitation persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        find_repo = FindingRepository(session)
        findings = [
            {
                "finding_id": "FND-CIS-CISCO-1.2",
                "control_id": "CIS-CISCO-1.2",
                "framework": "CIS",
                "title": "Unencrypted Telnet Enabled",
                "description": "Telnet daemon is accepting unencrypted cleartext management sessions.",
                "severity": "CRITICAL",
                "status": "FAIL",
                "category": "MANAGEMENT_SECURITY",
                "expected": "transport input ssh only",
                "observed": "transport input telnet ssh",
                "rationale": "Insecure protocol",
                "remediation_status": "NOT_REMEDIATED",
                "affected_files": ["router.cfg"],
                "evidence": [{"line": 42, "text": "transport input telnet ssh"}],
            }
        ]
        limitations = [
            {
                "control_id": "CIS-CISCO-9.9",
                "framework": "CIS",
                "title": "BGP MD5 Auth",
                "description": "BGP not configured",
                "affected_files": ["router.cfg"],
                "reason": "Feature absent",
            }
        ]
        saved = await find_repo.save_findings(audit_id, findings, limitations)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].finding_id == "FND-CIS-CISCO-1.2"

        fetched_lims = await find_repo.get_limitations(audit_id)
        assert len(fetched_lims) == 1
        assert fetched_lims[0].control_id == "CIS-CISCO-9.9"


@pytest.mark.asyncio
async def test_finding_evidence_persistence():
    """11. Test finding evidence line references persistence."""
    async with AsyncSessionLocal() as session:
        find_repo = FindingRepository(session)
        finding = await find_repo.get_finding("AUD-DBTEST-01", "FND-CIS-CISCO-1.2")
        assert finding is not None
        assert len(finding.evidence) == 1
        assert finding.evidence[0]["line"] == 42


@pytest.mark.asyncio
async def test_remediation_persistence():
    """12. Test remediation proposal persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        rem_repo = RemediationRepository(session)
        remediations = [
            {
                "remediation_id": "REM-FND-CIS-CISCO-1.2",
                "finding_id": "FND-CIS-CISCO-1.2",
                "control_id": "CIS-CISCO-1.2",
                "framework": "CIS",
                "vendor": "CISCO",
                "device_type": "ROUTER",
                "title": "Disable Telnet and Enforce SSH",
                "description": "Configure transport input ssh on VTY lines.",
                "status": "PROPOSED",
                "review_status": "PENDING",
                "proposed_commands": ["line vty 0 4", "transport input ssh"],
                "current_configuration": ["line vty 0 4", "transport input telnet ssh"],
                "proposed_configuration": ["line vty 0 4", "transport input ssh"],
                "validation_steps": ["show line vty 0 4"],
                "rollback_guidance": ["line vty 0 4", "transport input telnet ssh"],
                "affected_files": ["router.cfg"],
                "evidence": [{"line": 42, "text": "transport input telnet ssh"}],
                "manual_review_required": True,
                "required_inputs": [],
            }
        ]
        saved = await rem_repo.save_remediations(audit_id, remediations)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].remediation_id == "REM-FND-CIS-CISCO-1.2"


@pytest.mark.asyncio
async def test_ai_analysis_persistence():
    """13. Test AI analysis result persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        ai_repo = AIRepository(session)
        results = [
            {
                "file_id": "cfg_unknown_01",
                "analysis_method": "AI_LLM",
                "vendor_hypothesis": "MIKROTIK",
                "device_type": "ROUTER",
                "confidence": 0.88,
                "normalized_output": {"identity": {"hostname": {"value": "RouterOS-Core"}}},
                "requires_manual_validation": False,
            }
        ]
        saved = await ai_repo.save_ai_analysis_results(audit_id, results)
        await session.commit()
        assert len(saved) == 1
        assert saved[0].vendor_hypothesis == "MIKROTIK"


@pytest.mark.asyncio
async def test_ai_explanation_persistence():
    """14. Test AI explanation persistence."""
    async with AsyncSessionLocal() as session:
        audit_id = "AUD-DBTEST-01"
        ai_repo = AIRepository(session)
        explanation = {
            "finding_id": "FND-CIS-CISCO-1.2",
            "summary": "Telnet management enables cleartext password interception.",
            "security_impact": "Attacker on local network can capture admin credentials.",
            "evidence_interpretation": "Line 42 configures transport input telnet ssh.",
            "recommended_review": "Verify SSH keys exist before disabling Telnet.",
            "confidence": 0.92,
        }
        saved = await ai_repo.save_ai_explanation(audit_id, explanation)
        await session.commit()
        assert saved.id is not None
        assert saved.finding_id == "FND-CIS-CISCO-1.2"


@pytest.mark.asyncio
async def test_fk_relationships():
    """15. Test cascading deletion foreign-key relationship."""
    async with AsyncSessionLocal() as session:
        # Create a transient audit
        audit_repo = AuditRepository(session)
        cascade_id = "AUD-CASCADE-TEST"
        await audit_repo.create_audit(
            audit_id=cascade_id,
            status="UPLOADED",
            compliance_framework="CIS",
            original_filename="test.cfg",
            stored_path="/tmp/test.cfg",
            file_size=100,
        )
        
        # Add config file & finding
        config_repo = ConfigRepository(session)
        await config_repo.save_config_files(cascade_id, [{
            "file_id": "c1",
            "relative_path": "t.cfg",
            "original_filename": "t.cfg",
            "line_count": 10,
            "char_count": 100,
            "non_empty_line_count": 8,
            "comment_line_count": 2,
            "sha256": "abc",
            "encoding": "utf-8",
            "status": "VALID",
        }])
        await session.commit()

        # Delete audit
        audit_obj = await audit_repo.get_by_audit_id(cascade_id)
        await session.delete(audit_obj)
        await session.commit()

        # Check cascading deletion of config file
        configs = await config_repo.get_config_files(cascade_id)
        assert len(configs) == 0


@pytest.mark.asyncio
async def test_unique_constraints():
    """16. Test unique constraint enforcement on compliance results."""
    async with AsyncSessionLocal() as session:
        # Inserting duplicate (audit_id, control_id) should fail
        c1 = ComplianceResultModel(
            audit_id="AUD-DBTEST-01",
            control_id="DUP-CTRL-01",
            framework="CIS",
            title="Duplicate Test",
            severity="LOW",
            status="PASS",
            expected="X",
            observed="X",
            rationale="Test",
        )
        c2 = ComplianceResultModel(
            audit_id="AUD-DBTEST-01",
            control_id="DUP-CTRL-01",
            framework="CIS",
            title="Duplicate Test 2",
            severity="LOW",
            status="PASS",
            expected="X",
            observed="X",
            rationale="Test",
        )
        session.add(c1)
        await session.flush()
        session.add(c2)
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


@pytest.mark.asyncio
async def test_transaction_rollback():
    """17. Test transaction rollback on database error."""
    async with AsyncSessionLocal() as session:
        # Invalid FK insertion should trigger rollback
        invalid_item = ComplianceResultModel(
            audit_id="NON_EXISTENT_AUDIT_ID",
            control_id="CTRL-BAD",
            framework="CIS",
            title="Bad",
            severity="LOW",
            status="FAIL",
            expected="E",
            observed="O",
            rationale="R",
        )
        session.add(invalid_item)
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


@pytest.mark.asyncio
async def test_audit_history_pagination():
    """18. Test paginated audit history retrieval."""
    async with AsyncSessionLocal() as session:
        repo = AuditRepository(session)
        audits, total = await repo.list_audits(page=1, page_size=10)
        assert total >= 1
        assert len(audits) >= 1


@pytest.mark.asyncio
async def test_audit_history_filtering():
    """19. Test audit history filtering by status and framework."""
    async with AsyncSessionLocal() as session:
        repo = AuditRepository(session)
        audits, total = await repo.list_audits(page=1, page_size=10, framework="CIS")
        assert total >= 1
        for a in audits:
            assert a.compliance_framework == "CIS"


@pytest.mark.asyncio
async def test_restart_persistence():
    """20. Critical Acceptance Test — Verify persistence across service restart simulation."""
    # Create fresh AuditService instance (simulating backend process restart)
    new_service = AuditService()
    reconstituted_audit = await new_service.get_audit("AUD-DBTEST-01")

    assert reconstituted_audit is not None
    assert reconstituted_audit.audit_id == "AUD-DBTEST-01"
    assert reconstituted_audit.filename == "router.cfg"
    assert reconstituted_audit.inventory is not None
    assert reconstituted_audit.detection_summary is not None
    assert reconstituted_audit.parsing_summary is not None
    assert reconstituted_audit.normalization_summary is not None
    assert reconstituted_audit.compliance_summary is not None
    assert reconstituted_audit.findings_summary is not None
    assert reconstituted_audit.remediation_summary is not None

    # Check evidence traceability after restart
    finding = await new_service.get_finding("AUD-DBTEST-01", "FND-CIS-CISCO-1.2")
    assert finding is not None
    assert finding.severity == "CRITICAL"
    line = finding.evidence[0].source_line if hasattr(finding.evidence[0], "source_line") else finding.evidence[0]["line"]
    assert line == 42
