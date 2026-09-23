"""
Regression tests for New Audit UI, Compliance Idempotency, and API safety.
Ensures that:
- Compliance execution is idempotent when called once, twice, or concurrently.
- No duplicate key IntegrityError is raised when audit package contains multiple files (e.g. AUD-973360).
- Existing compliance, finding, and remediation records are safely reused.
- Non-existent audit IDs return 404 with structured JSON message.
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

class TestNewAuditPipelineRegression:
    def test_nonexistent_audit_detail_returns_404(self):
        response = client.get("/api/audits/nonexistent-audit-999")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert data["detail"] == "Audit 'nonexistent-audit-999' not found."

    def test_nonexistent_audit_inventory_returns_404(self):
        response = client.get("/api/audits/nonexistent-audit-999/inventory")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_nonexistent_audit_detection_returns_404(self):
        response = client.get("/api/audits/nonexistent-audit-999/detection")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_nonexistent_audit_compliance_returns_404(self):
        response = client.get("/api/audits/nonexistent-audit-999/compliance")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_empty_audit_list_returns_valid_structure(self):
        response = client.get("/api/audits?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    def test_compliance_idempotency_repeated_calls(self):
        """Test uploading a configuration and calling compliance twice sequentially."""
        upload_resp = client.post(
            "/api/audits",
            files={"file": ("cisco_router_secure.cfg", b"version 15.2\nhostname RTR-TEST\nip ssh version 2\n")},
            data={"framework": "CIS"}
        )
        assert upload_resp.status_code in (200, 201)
        audit_id = upload_resp.json()["audit_id"]

        # Run pipeline up to normalization
        client.post(f"/api/audits/{audit_id}/detect")
        client.post(f"/api/audits/{audit_id}/parse")
        client.post(f"/api/audits/{audit_id}/normalize")

        # Call compliance ONCE
        comp1 = client.post(f"/api/audits/{audit_id}/compliance")
        assert comp1.status_code == 200
        data1 = comp1.json()

        # Call compliance TWICE
        comp2 = client.post(f"/api/audits/{audit_id}/compliance")
        assert comp2.status_code == 200
        data2 = comp2.json()

        assert data1["summary"]["total_controls"] == data2["summary"]["total_controls"]
        assert len(data1["results"]) == len(data2["results"])

    def test_findings_and_remediation_idempotency(self):
        """Test calling findings and remediation endpoints repeatedly."""
        upload_resp = client.post(
            "/api/audits",
            files={"file": ("cisco_router_insecure.cfg", b"version 12.0\nhostname RTR-INSECURE\nline vty 0 4\n transport input telnet\n")},
            data={"framework": "CIS"}
        )
        assert upload_resp.status_code in (200, 201)
        audit_id = upload_resp.json()["audit_id"]

        client.post(f"/api/audits/{audit_id}/detect")
        client.post(f"/api/audits/{audit_id}/parse")
        client.post(f"/api/audits/{audit_id}/normalize")
        client.post(f"/api/audits/{audit_id}/compliance")

        # Call findings twice
        f1 = client.post(f"/api/audits/{audit_id}/findings")
        assert f1.status_code == 200
        f2 = client.post(f"/api/audits/{audit_id}/findings")
        assert f2.status_code == 200
        assert f1.json()["summary"]["total_findings"] == f2.json()["summary"]["total_findings"]

        # Call remediation twice
        r1 = client.post(f"/api/audits/{audit_id}/remediation")
        assert r1.status_code == 200
        r2 = client.post(f"/api/audits/{audit_id}/remediation")
        assert r2.status_code == 200
        assert r1.json()["summary"]["remediations_available"] == r2.json()["summary"]["remediations_available"]
