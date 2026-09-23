"""
Tests — Audit upload endpoints
================================
Covers all 10 required test cases:

 1. Health endpoint                    → 200
 2. Valid .cfg upload                  → 201
 3. Valid .conf upload                 → 201
 4. Valid .txt upload                  → 201
 5. Valid .zip upload                  → 201
 6. Invalid extension (.exe)           → 400
 7. File larger than 50 MB             → 413
 8. GET uploaded audit                 → 200
 9. GET unknown audit                  → 404
10. GET audits list                    → 200
"""

import io

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings


@pytest.fixture(scope="module")
def client():
    """Single TestClient reused across all tests in this module."""
    with TestClient(app) as c:
        yield c


# ─── Helper ──────────────────────────────────────────────────────────────────

def _upload(client, filename: str, content: bytes = b"hostname router\n", framework: str = "CIS"):
    """POST a file to /api/audits and return the response."""
    return client.post(
        "/api/audits",
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
        data={"framework": framework},
    )


# ─── Test cases ──────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_ok(self, client):
        """Test case 1: Health endpoint returns 200."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestValidUploads:
    def test_cfg_upload(self, client):
        """Test case 2: .cfg file → 201."""
        resp = _upload(client, "router.cfg")
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] in ("UPLOADED", "READY_FOR_DETECTION")
        assert body["audit_id"].startswith("AUD-")
        assert body["filename"].endswith(".cfg")
        assert body["framework"] == "CIS"
        assert "successfully" in body["message"].lower()

    def test_conf_upload(self, client):
        """Test case 3: .conf file → 201."""
        resp = _upload(client, "firewall.conf", framework="NIST")
        assert resp.status_code == 201
        assert resp.json()["framework"] == "NIST"

    def test_txt_upload(self, client):
        """Test case 4: .txt file → 201."""
        resp = _upload(client, "switch_config.txt", framework="STIG")
        assert resp.status_code == 201
        assert resp.json()["framework"] == "STIG"

    def test_zip_upload(self, client):
        """Test case 5: .zip file → 201."""
        # Minimal valid zip-like bytes (does NOT need to be a real ZIP for upload validation)
        zip_bytes = b"PK\x03\x04" + b"\x00" * 26  # ZIP local file header magic
        resp = _upload(client, "configs.zip", content=zip_bytes)
        assert resp.status_code == 201

    def test_audit_id_uniqueness(self, client):
        """Each upload should receive a different audit ID."""
        r1 = _upload(client, "a.cfg")
        r2 = _upload(client, "b.cfg")
        assert r1.json()["audit_id"] != r2.json()["audit_id"]


class TestRejectedUploads:
    def test_invalid_extension_exe(self, client):
        """Test case 6: .exe extension → 400."""
        resp = _upload(client, "malware.exe")
        assert resp.status_code == 400
        assert "unsupported" in resp.json()["detail"].lower()

    def test_invalid_extension_py(self, client):
        """Python script → 400."""
        resp = _upload(client, "exploit.py")
        assert resp.status_code == 400

    def test_invalid_extension_sh(self, client):
        """Shell script → 400."""
        resp = _upload(client, "setup.sh")
        assert resp.status_code == 400

    def test_oversized_file(self, client):
        """Test case 7: file > 50 MB → 413."""
        # Generate a file that is exactly MAX_UPLOAD_BYTES + 1 byte
        oversized = b"A" * (settings.MAX_UPLOAD_BYTES + 1)
        resp = _upload(client, "huge.cfg", content=oversized)
        assert resp.status_code == 413
        assert "limit" in resp.json()["detail"].lower()


class TestAuditRetrieval:
    def test_get_audit_after_upload(self, client):
        """Test case 8: GET /api/audits/{audit_id} → 200 with correct metadata."""
        upload_resp = _upload(client, "test_device.cfg")
        assert upload_resp.status_code == 201
        audit_id = upload_resp.json()["audit_id"]

        get_resp = client.get(f"/api/audits/{audit_id}")
        assert get_resp.status_code == 200

        body = get_resp.json()
        assert body["audit_id"] == audit_id
        assert body["filename"] == "test_device.cfg"
        assert body["status"] in ("UPLOADED", "READY_FOR_DETECTION")
        assert body["file_size"] > 0
        assert "created_at" in body

    def test_get_unknown_audit(self, client):
        """Test case 9: GET /api/audits/NONEXISTENT → 404."""
        resp = client.get("/api/audits/AUD-DOESNOTEXIST")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_list_audits(self, client):
        """Test case 10: GET /api/audits → 200 with items list."""
        # Upload something to guarantee the list is non-empty
        _upload(client, "list_test.cfg")

        resp = client.get("/api/audits")
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body
        assert isinstance(body["items"], list)
        assert body["total"] >= len(body["items"])
        assert body["total"] >= 1

    def test_list_audits_newest_first(self, client):
        """Audits should be returned in reverse-chronological order."""
        r1 = _upload(client, "first.cfg")
        r2 = _upload(client, "second.cfg")
        id1 = r1.json()["audit_id"]
        id2 = r2.json()["audit_id"]

        resp = client.get("/api/audits")
        ids = [item["audit_id"] for item in resp.json()["items"]]
        # id2 (uploaded later) should appear before id1
        assert ids.index(id2) < ids.index(id1)


class TestFrameworkHandling:
    def test_all_supported_frameworks(self, client):
        """CIS, NIST, STIG should all be accepted."""
        for fw in ["CIS", "NIST", "STIG"]:
            resp = _upload(client, f"device_{fw.lower()}.cfg", framework=fw)
            assert resp.status_code == 201, f"Framework {fw} was rejected"
            assert resp.json()["framework"] == fw

    def test_invalid_framework(self, client):
        """Unknown framework value → 422 (Pydantic validation)."""
        resp = _upload(client, "device.cfg", framework="UNKNOWN_FW")
        assert resp.status_code == 422

    def test_filename_sanitisation(self, client):
        """Spaces and special chars in filenames should be sanitised."""
        resp = _upload(client, "my device config.cfg")
        assert resp.status_code == 201
        # Sanitised filename should not contain spaces
        assert " " not in resp.json()["filename"]
