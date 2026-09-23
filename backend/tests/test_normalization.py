"""
Unit tests for Block 6: Vendor-Neutral Configuration Normalization
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsers import CiscoParser, JuniperParser, FortinetParser
from app.normalization import (
    normalizer_registry,
    CiscoNormalizer,
    JuniperNormalizer,
    FortinetNormalizer,
    NormalizationStatusEnum,
    netmask_to_prefix,
    format_ip_cidr,
)

client = TestClient(app)

# ─────────────────────────────────────────────────────────────────────────────
# Sample Configs
# ─────────────────────────────────────────────────────────────────────────────

CISCO_SAMPLE = """!
hostname CORE-ROUTER-01
enable secret 5 $1$mER7$j1Q5cQ
username admin privilege 15 secret 5 $1$mER7$j1Q5cQ
!
interface GigabitEthernet0/1
 description Uplink Interface
 ip address 192.168.1.1 255.255.255.0
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10,20
!
interface GigabitEthernet0/2
 description Downlink Interface
 ip address 10.0.0.1 255.255.255.128
 shutdown
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
!
access-list 100 permit ip any any
!
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
!
logging host 10.10.10.50
ntp server 10.10.10.1
"""

JUNIPER_SAMPLE = """
set system host-name JUNIPER-EX-01
set system services ssh protocol-version v2
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security policies from-zone trust to-zone untrust policy allow-all then permit
"""

FORTINET_SAMPLE = """
config system global
    set hostname FGT-FW-01
end

config system interface
    edit "port1"
        set vdom "root"
        set ip 172.16.1.1 255.255.255.0
        set allowaccess ping ssh https
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

# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests for Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def test_netmask_to_prefix():
    assert netmask_to_prefix("255.255.255.0") == 24
    assert netmask_to_prefix("255.255.255.128") == 25
    assert netmask_to_prefix("255.0.0.0") == 8
    assert netmask_to_prefix("invalid") is None
    assert netmask_to_prefix(None) is None

def test_format_ip_cidr():
    assert format_ip_cidr("192.168.1.1", "255.255.255.0") == "192.168.1.1/24"
    assert format_ip_cidr("10.0.0.1/24", None) == "10.0.0.1/24"
    assert format_ip_cidr("10.0.0.1", None) == "10.0.0.1"

# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests for Cisco Normalization
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_normalization():
    parser = CiscoParser()
    parsed = parser.parse("cisco.cfg", CISCO_SAMPLE, "ROUTER")
    normalizer = CiscoNormalizer()
    normalized = normalizer.normalize(parsed)

    assert normalized.status == NormalizationStatusEnum.NORMALIZED
    assert normalized.vendor.upper() == "CISCO"
    assert normalized.identity.hostname == "CORE-ROUTER-01"
    assert normalized.authentication.enable_secret_present is True

    # Management
    assert normalized.management.ssh.enabled is True
    assert normalized.management.ssh.version == "2"

    # Interfaces & CIDR conversion
    assert len(normalized.interfaces) == 2
    if1 = normalized.interfaces[0]
    assert if1.name == "GigabitEthernet0/1"
    assert if1.ip_addresses == ["192.168.1.1/24"]
    assert if1.enabled is True

    if2 = normalized.interfaces[1]
    assert if2.name == "GigabitEthernet0/2"
    assert if2.ip_addresses == ["10.0.0.1/25"]
    assert if2.enabled is False

    # Routes
    assert len(normalized.routing.static_routes) == 1
    assert normalized.routing.static_routes[0]["next_hop"] == "192.168.1.254"

    # Logging & NTP
    assert len(normalized.logging.remote_servers) == 1
    assert normalized.logging.remote_servers[0] == "10.10.10.50"
    assert len(normalized.ntp.servers) == 1
    assert normalized.ntp.servers[0] == "10.10.10.1"

    # Evidence preservation
    assert len(normalized.evidence) > 0

# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests for Juniper Normalization
# ─────────────────────────────────────────────────────────────────────────────

def test_juniper_normalization():
    parser = JuniperParser()
    parsed = parser.parse("juniper.cfg", JUNIPER_SAMPLE, "SWITCH")
    normalizer = JuniperNormalizer()
    normalized = normalizer.normalize(parsed)

    assert normalized.status == NormalizationStatusEnum.NORMALIZED
    assert normalized.vendor.upper() == "JUNIPER"
    assert normalized.identity.hostname == "JUNIPER-EX-01"
    assert normalized.management.ssh.enabled is True

    assert len(normalized.interfaces) == 1
    assert normalized.interfaces[0].ip_addresses == ["10.0.0.1/24"]

    assert len(normalized.security_zones) == 1
    assert normalized.security_zones[0].name == "trust"
    assert len(normalized.firewall_policies) == 1
    assert normalized.firewall_policies[0].action == "PERMIT"

# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests for Fortinet Normalization
# ─────────────────────────────────────────────────────────────────────────────

def test_fortinet_normalization():
    parser = FortinetParser()
    parsed = parser.parse("fortinet.cfg", FORTINET_SAMPLE, "FIREWALL")
    normalizer = FortinetNormalizer()
    normalized = normalizer.normalize(parsed)

    assert normalized.status == NormalizationStatusEnum.NORMALIZED
    assert normalized.vendor.upper() == "FORTINET"
    assert normalized.identity.hostname == "FGT-FW-01"
    assert normalized.management.ssh.enabled is True
    assert normalized.management.https.enabled is True

    assert len(normalized.interfaces) == 1
    assert normalized.interfaces[0].name == "port1"
    assert normalized.interfaces[0].ip_addresses == ["172.16.1.1/24"]

    assert len(normalized.firewall_policies) == 1
    assert normalized.firewall_policies[0].action == "ACCEPT"

# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests for Registry & Unknown Vendor
# ─────────────────────────────────────────────────────────────────────────────

def test_normalizer_registry():
    assert isinstance(normalizer_registry.get_normalizer("CISCO"), CiscoNormalizer)
    assert isinstance(normalizer_registry.get_normalizer("JUNIPER"), JuniperNormalizer)
    assert isinstance(normalizer_registry.get_normalizer("FORTINET"), FortinetNormalizer)
    assert normalizer_registry.get_normalizer("UNKNOWN") is None
    assert normalizer_registry.get_normalizer("LINUX") is None

# ─────────────────────────────────────────────────────────────────────────────
# Full API Workflow Integration Test
# ─────────────────────────────────────────────────────────────────────────────

def test_normalization_api_workflow():
    # 1. Upload audit
    content = CISCO_SAMPLE.encode("utf-8")
    response = client.post(
        "/api/audits",
        files={"file": ("cisco_test.cfg", io.BytesIO(content), "text/plain")},
        data={"framework": "CIS"},
    )
    assert response.status_code == 201
    data = response.json()
    audit_id = data["audit_id"]

    # 2. Ingest
    ingest_resp = client.post(f"/api/audits/{audit_id}/ingest")
    assert ingest_resp.status_code == 200

    # 3. Detect
    detect_resp = client.post(f"/api/audits/{audit_id}/detect")
    assert detect_resp.status_code == 200

    # 4. Parse
    parse_resp = client.post(f"/api/audits/{audit_id}/parse")
    assert parse_resp.status_code == 200

    # 5. Normalize
    norm_resp = client.post(f"/api/audits/{audit_id}/normalize")
    assert norm_resp.status_code == 200
    norm_data = norm_resp.json()
    assert norm_data["status"] == "NORMALIZATION_COMPLETE"
    assert norm_data["total_files"] == 1
    assert norm_data["normalized_files"] == 1

    # 6. GET audit normalization summary
    get_norm = client.get(f"/api/audits/{audit_id}/normalization")
    assert get_norm.status_code == 200
    summary_data = get_norm.json()
    assert summary_data["audit_id"] == audit_id
    assert len(summary_data["files"]) == 1

    file_id = summary_data["files"][0]["file_id"]

    # 7. GET file normalization detail
    file_norm = client.get(f"/api/audits/{audit_id}/normalization/{file_id}")
    assert file_norm.status_code == 200
    detail = file_norm.json()
    assert detail["vendor"].upper() == "CISCO"
    assert detail["identity"]["hostname"] == "CORE-ROUTER-01"
    assert len(detail["evidence"]) > 0
