"""
Unit tests for Block 3: Configuration Ingestion & Discovery Pipeline
"""

import io
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.audit import AuditStatus
from app.models.inventory import ConfigStatus
from app.services.ingestion_service import extract_candidate_hostname, ingestion_service

client = TestClient(app)

SAMPLE_CISCO_CONFIG = """!
! Last configuration change at 14:32:01 UTC Tue Sep 22 2026
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname Core_Gateway_Router01
!
boot-start-marker
boot-end-marker
!
no aaa new-model
!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 duplex auto
 speed auto
!
end
"""

SAMPLE_JUNIPER_CONFIG = """
system {
    host-name Junos_Border_Switch;
    domain-name corp.internal;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
"""


def test_extract_candidate_hostname():
    assert extract_candidate_hostname(SAMPLE_CISCO_CONFIG) == "Core_Gateway_Router01"
    assert extract_candidate_hostname(SAMPLE_JUNIPER_CONFIG) == "Junos_Border_Switch"
    assert extract_candidate_hostname("random text without hostname") is None


def test_single_file_ingestion(tmp_path):
    cfg_file = tmp_path / "cisco.cfg"
    cfg_file.write_text(SAMPLE_CISCO_CONFIG, encoding="utf-8")

    inventory = ingestion_service.process_audit_file(
        audit_id="AUD-TEST1",
        file_path=cfg_file,
        audit_dir=tmp_path,
    )

    assert inventory.audit_id == "AUD-TEST1"
    assert inventory.total_files_discovered == 1
    assert inventory.valid_configs_count == 1
    assert inventory.skipped_files_count == 0
    assert len(inventory.files) == 1

    file_meta = inventory.files[0]
    assert file_meta.relative_path == "cisco.cfg"
    assert file_meta.status == ConfigStatus.VALID
    assert file_meta.candidate_hostname == "Core_Gateway_Router01"
    assert file_meta.line_count > 15
    assert file_meta.comment_line_count > 5
    assert len(file_meta.sha256) == 64


def test_zip_archive_ingestion(tmp_path):
    zip_path = tmp_path / "multi_configs.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("cisco_router.cfg", SAMPLE_CISCO_CONFIG)
        zf.writestr("juniper_switch.conf", SAMPLE_JUNIPER_CONFIG)
        zf.writestr("__MACOSX/._cisco_router.cfg", "mac metadata")

    inventory = ingestion_service.process_audit_file(
        audit_id="AUD-TEST2",
        file_path=zip_path,
        audit_dir=tmp_path,
    )

    assert inventory.audit_id == "AUD-TEST2"
    assert inventory.total_files_discovered == 2
    assert inventory.valid_configs_count == 2
    assert inventory.skipped_files_count == 0
    hostnames = {f.candidate_hostname for f in inventory.files}
    assert "Core_Gateway_Router01" in hostnames
    assert "Junos_Border_Switch" in hostnames


def test_zip_slip_protection(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zf.writestr("valid_config.cfg", SAMPLE_CISCO_CONFIG)

    inventory = ingestion_service.process_audit_file(
        audit_id="AUD-TEST3",
        file_path=zip_path,
        audit_dir=tmp_path,
    )

    # Malicious file should be skipped by zip-slip check
    paths = [f.relative_path for f in inventory.files]
    assert "../../../etc/passwd" not in paths
    assert "valid_config.cfg" in paths


def test_upload_and_inventory_api():
    # 1. Upload file
    response = client.post(
        "/api/audits",
        files={"file": ("cisco_router.cfg", io.BytesIO(SAMPLE_CISCO_CONFIG.encode("utf-8")), "text/plain")},
        data={"framework": "CIS"},
    )
    assert response.status_code == 201
    data = response.json()
    audit_id = data["audit_id"]

    # 2. Check detail status (should be READY_FOR_DETECTION)
    detail_res = client.get(f"/api/audits/{audit_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["status"] == AuditStatus.READY_FOR_DETECTION.value
    assert detail["inventory"] is not None
    assert detail["inventory"]["valid_configs_count"] == 1

    # 3. Get inventory directly
    inv_res = client.get(f"/api/audits/{audit_id}/inventory")
    assert inv_res.status_code == 200
    inv = inv_res.json()
    assert inv["audit_id"] == audit_id
    assert inv["files"][0]["candidate_hostname"] == "Core_Gateway_Router01"

    # 4. Re-trigger ingestion endpoint
    ingest_res = client.post(f"/api/audits/{audit_id}/ingest")
    assert ingest_res.status_code == 200
    assert ingest_res.json()["status"] == AuditStatus.READY_FOR_DETECTION.value
