"""
Unit tests for Block 4: Vendor & Device Detection Engine
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.detection import vendor_detector
from app.main import app
from app.models.detection import (
    DetectionMethodEnum,
    DetectionStatusEnum,
    DeviceTypeEnum,
    VendorEnum,
)

client = TestClient(app)

# ── Sample Config Snippets ───────────────────────────────────────────────────

CISCO_ROUTER_CONFIG = """!
version 15.4
hostname Border_Router_01
!
boot-start-marker
boot-end-marker
!
ip cef
!
router ospf 100
 network 10.0.0.0 0.255.255.255 area 0
!
ip route 0.0.0.0 0.0.0.0 192.168.1.1
!
line vty 0 4
 transport input ssh
!
end
"""

CISCO_SWITCH_CONFIG = """!
version 15.2
hostname Core_Switch_01
!
spanning-tree mode rapid-pvst
vlan 10,20,30
!
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
!
end
"""

JUNIPER_SET_CONFIG = """
set system host-name Junos_Gateway
set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security policies from-zone trust to-zone untrust policy allow-all match source-address any
set security policies from-zone trust to-zone untrust policy allow-all match destination-address any
set security policies from-zone trust to-zone untrust policy allow-all match application any
set security policies from-zone trust to-zone untrust policy allow-all then permit
"""

JUNIPER_HIERARCHICAL_CONFIG = """
system {
    host-name Junos_HQ_Switch;
    services {
        ssh;
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 {
            family ethernet-switching {
                vlan {
                    members corp-vlan;
                }
            }
        }
    }
}
vlans {
    corp-vlan {
        vlan-id 100;
    }
}
"""

FORTINET_FIREWALL_CONFIG = """
config system global
    set hostname "FortiGate-500E"
    set timezone 04
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 172.16.1.1 255.255.255.0
        set allowaccess ping https ssh
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""

GENERIC_WEAK_CONFIG = """
# Generic Linux network setup
hostname generic-box
interface eth0
ip address 192.168.1.50
"""

UNKNOWN_LINUX_CONFIG = """
# /etc/sysconfig/network-scripts/ifcfg-eth0
DEVICE=eth0
BOOTPROTO=dhcp
ONBOOT=yes
TYPE=Ethernet
USERCTL=no
"""


# ── Unit Tests: Vendor Detector ──────────────────────────────────────────────

def test_cisco_router_detection():
    res = vendor_detector.detect_file("CFG-001", "cisco_router.cfg", CISCO_ROUTER_CONFIG)
    assert res.vendor == VendorEnum.CISCO
    assert res.device_type == DeviceTypeEnum.ROUTER
    assert res.confidence >= 0.70
    assert res.status == DetectionStatusEnum.KNOWN
    assert res.method == DetectionMethodEnum.DETERMINISTIC
    assert len(res.evidence) >= 4
    indicators = [e.indicator for e in res.evidence]
    assert "version <number>" in indicators


def test_cisco_switch_detection():
    res = vendor_detector.detect_file("CFG-002", "cisco_switch.cfg", CISCO_SWITCH_CONFIG)
    assert res.vendor == VendorEnum.CISCO
    assert res.device_type == DeviceTypeEnum.SWITCH
    assert res.confidence >= 0.60
    assert res.status == DetectionStatusEnum.KNOWN


def test_juniper_set_detection():
    res = vendor_detector.detect_file("CFG-003", "junos_fw.conf", JUNIPER_SET_CONFIG)
    assert res.vendor == VendorEnum.JUNIPER
    assert res.device_type == DeviceTypeEnum.FIREWALL
    assert res.confidence >= 0.70
    assert len(res.evidence) >= 3


def test_juniper_hierarchical_detection():
    res = vendor_detector.detect_file("CFG-004", "junos_hq.conf", JUNIPER_HIERARCHICAL_CONFIG)
    assert res.vendor == VendorEnum.JUNIPER
    assert res.device_type == DeviceTypeEnum.SWITCH
    assert res.confidence >= 0.50


def test_fortinet_firewall_detection():
    res = vendor_detector.detect_file("CFG-005", "fortigate.conf", FORTINET_FIREWALL_CONFIG)
    assert res.vendor == VendorEnum.FORTINET
    assert res.device_type == DeviceTypeEnum.FIREWALL
    assert res.confidence >= 0.70
    indicators = [e.indicator for e in res.evidence]
    assert "config firewall policy" in indicators


def test_unknown_generic_weak_config():
    res = vendor_detector.detect_file("CFG-006", "generic.conf", GENERIC_WEAK_CONFIG)
    # Generic hostname/interface/ip address must NOT independently classify Cisco
    assert res.vendor == VendorEnum.UNKNOWN
    assert res.device_type == DeviceTypeEnum.UNKNOWN
    assert res.confidence == 0.0
    assert res.status == DetectionStatusEnum.UNKNOWN_VENDOR


def test_unknown_linux_config():
    res = vendor_detector.detect_file("CFG-007", "ifcfg-eth0", UNKNOWN_LINUX_CONFIG)
    assert res.vendor == VendorEnum.UNKNOWN
    assert res.device_type == DeviceTypeEnum.UNKNOWN
    assert res.status == DetectionStatusEnum.UNKNOWN_VENDOR


# ── Integration Tests: API Endpoints ──────────────────────────────────────────

def test_detect_api_flow():
    # 1. Upload a Cisco router config
    upload_res = client.post(
        "/api/audits",
        files={"file": ("border_router.cfg", io.BytesIO(CISCO_ROUTER_CONFIG.encode("utf-8")), "text/plain")},
        data={"framework": "CIS"},
    )
    assert upload_res.status_code == 201
    audit_id = upload_res.json()["audit_id"]

    # 2. Call POST /api/audits/{audit_id}/detect
    detect_res = client.post(f"/api/audits/{audit_id}/detect")
    assert detect_res.status_code == 200
    summary = detect_res.json()

    assert summary["audit_id"] == audit_id
    assert summary["status"] == "DETECTION_COMPLETE"
    assert summary["total_files"] == 1
    assert summary["detected_files"] == 1
    assert len(summary["files"]) == 1

    file_det = summary["files"][0]
    assert file_det["vendor"] == "Cisco"
    assert file_det["device_type"] == "Router"
    assert file_det["confidence"] > 0.7
    assert len(file_det["evidence"]) > 0

    # 3. Call GET /api/audits/{audit_id}/detection
    get_det_res = client.get(f"/api/audits/{audit_id}/detection")
    assert get_det_res.status_code == 200
    assert get_det_res.json()["audit_id"] == audit_id


def test_detect_unknown_audit():
    res = client.post("/api/audits/AUD-DOESNOTEXIST/detect")
    assert res.status_code == 404
