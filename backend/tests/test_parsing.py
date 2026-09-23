"""
Unit tests for Block 5: Vendor-Specific Configuration Parsing
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsers import (
    CiscoParser,
    FortinetParser,
    JuniperParser,
    ParserStatusEnum,
    parser_registry,
)

client = TestClient(app)

# ── Sample Config Snippets ───────────────────────────────────────────────────

CISCO_FULL_CONFIG = """!
version 15.4
hostname CORE-SW-01
!
enable secret 5 $1$mER7$j1Q5cQ
username admin privilege 15 secret 5 $1$mER7$j1Q5cQ
!
vlan 10
 name USERS
vlan 20
 name SERVERS
!
interface GigabitEthernet0/1
 description Uplink-Router
 ip address 10.0.0.1 255.255.255.0
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10,20
!
interface GigabitEthernet0/2
 description User-Port
 switchport mode access
 switchport access vlan 10
 shutdown
!
ip route 0.0.0.0 0.0.0.0 10.0.0.254
!
router ospf 100
 network 10.0.0.0 0.255.255.255 area 0
!
router bgp 65001
!
access-list 10 permit 192.168.1.0 0.0.0.255
ip access-list extended SECURE_ACL
!
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
!
logging host 10.10.10.50
logging buffered 64000
!
ntp server 10.10.10.10
"""

JUNIPER_SET_CONFIG = """
set system host-name SRX-01
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set interfaces ge-0/0/0 description "WLAN Interface"
set security zones security-zone trust interfaces ge-0/0/0.0
set security policies from-zone trust to-zone untrust policy allow-web
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
set protocols ospf
set protocols bgp
set system services ssh
set system ntp server 10.10.10.10
set system syslog host 10.10.10.50
"""

JUNIPER_HIERARCHICAL_CONFIG = """
system {
    host-name SRX-HQ;
    services {
        ssh;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 172.16.0.1/24;
            }
        }
    }
}
"""

FORTINET_FULL_CONFIG = """
config system global
    set hostname FGT-01
    set vdom "root"
end
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh
        set description "WAN Interface"
    next
end
config firewall policy
    edit 1
        set name "Allow-Web"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set schedule "always"
    next
end
config firewall address
    edit "Corp_Subnet"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 10.0.0.254
        set device "port1"
    next
end
config vpn ike
end
config system ntp
    set ntpserver "10.10.10.10"
end
"""


# ── CISCO PARSER TESTS ────────────────────────────────────────────────────────

def test_cisco_hostname_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    assert res.data["hostname"] == "CORE-SW-01"
    assert any(e.field == "hostname" and e.line == 3 for e in res.evidence)

def test_cisco_interface_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    ifs = res.data["interfaces"]
    assert len(ifs) >= 2
    ge1 = next(i for i in ifs if i["name"] == "GigabitEthernet0/1")
    assert ge1["description"] == "Uplink-Router"
    assert ge1["ip_addresses"] == [{"ip": "10.0.0.1", "netmask": "255.255.255.0"}]
    assert ge1["switchport"]["mode"] == "trunk"

def test_cisco_ip_address_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    ge1 = next(i for i in res.data["interfaces"] if i["name"] == "GigabitEthernet0/1")
    assert len(ge1["ip_addresses"]) == 1
    assert ge1["ip_addresses"][0]["ip"] == "10.0.0.1"

def test_cisco_switchport_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    ge2 = next(i for i in res.data["interfaces"] if i["name"] == "GigabitEthernet0/2")
    assert ge2["switchport"]["mode"] == "access"
    assert ge2["switchport"]["access_vlan"] == 10
    assert ge2["shutdown"] is True

def test_cisco_vlan_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    vlans = res.data["vlans"]
    assert len(vlans) == 2
    assert vlans[0] == {"vlan_id": 10, "name": "USERS"}
    assert vlans[1] == {"vlan_id": 20, "name": "SERVERS"}

def test_cisco_ospf_detection():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Router")
    assert res.data["routing"]["ospf"] is not None
    assert res.data["routing"]["ospf"]["process_id"] == 100

def test_cisco_bgp_detection():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Router")
    assert res.data["routing"]["bgp"] == {"as_number": 65001}

def test_cisco_static_route_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Router")
    routes = res.data["routing"]["static_routes"]
    assert len(routes) == 1
    assert routes[0]["destination"] == "0.0.0.0"
    assert routes[0]["next_hop"] == "10.0.0.254"

def test_cisco_ssh_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    assert res.data["management"]["ssh_version"] == "2"
    vtys = res.data["management"]["line_vty"]
    assert len(vtys) == 1
    assert vtys[0]["transport_input"] == "ssh"
    assert vtys[0]["login_local"] is True

def test_cisco_ntp_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    assert res.data["ntp"]["servers"] == ["10.10.10.10"]

def test_cisco_acl_parsing():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    acls = res.data["acls"]
    assert len(acls) == 2
    assert acls[0]["name"] == "10"
    assert acls[1]["name"] == "SECURE_ACL"


# ── JUNIPER PARSER TESTS ──────────────────────────────────────────────────────

def test_juniper_set_hostname():
    res = JuniperParser().parse("CFG-002", JUNIPER_SET_CONFIG, "Firewall")
    assert res.data["hostname"] == "SRX-01"

def test_juniper_set_interface():
    res = JuniperParser().parse("CFG-002", JUNIPER_SET_CONFIG, "Firewall")
    ifs = res.data["interfaces"]
    assert len(ifs) >= 1
    ge0 = next(i for i in ifs if i["name"] == "ge-0/0/0")
    assert ge0["ip_addresses"] == ["10.0.0.1/24"]

def test_juniper_set_security_zone():
    res = JuniperParser().parse("CFG-002", JUNIPER_SET_CONFIG, "Firewall")
    zones = res.data["security"]["zones"]
    assert len(zones) == 1
    assert zones[0]["name"] == "trust"

def test_juniper_set_routing():
    res = JuniperParser().parse("CFG-002", JUNIPER_SET_CONFIG, "Router")
    assert res.data["routing"]["ospf"] is True
    assert res.data["routing"]["bgp"] is True
    assert len(res.data["routing"]["static_routes"]) == 1

def test_juniper_hierarchical_hostname():
    res = JuniperParser().parse("CFG-003", JUNIPER_HIERARCHICAL_CONFIG, "Switch")
    assert res.data["hostname"] == "SRX-HQ"

def test_juniper_hierarchical_interface():
    res = JuniperParser().parse("CFG-003", JUNIPER_HIERARCHICAL_CONFIG, "Switch")
    ifs = res.data["interfaces"]
    assert len(ifs) >= 1
    assert "172.16.0.1/24" in ifs[0]["ip_addresses"]

def test_juniper_hierarchical_services():
    res = JuniperParser().parse("CFG-003", JUNIPER_HIERARCHICAL_CONFIG, "Switch")
    assert res.data["management"]["ssh_enabled"] is True


# ── FORTINET PARSER TESTS ─────────────────────────────────────────────────────

def test_fortinet_hostname():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    assert res.data["hostname"] == "FGT-01"
    assert res.data["vdom"] == "root"

def test_fortinet_interface():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    ifs = res.data["interfaces"]
    assert len(ifs) == 1
    assert ifs[0]["name"] == "port1"
    assert ifs[0]["ip"] == "10.0.0.1 255.255.255.0"
    assert "ssh" in ifs[0]["allowaccess"]

def test_fortinet_firewall_policy():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    pols = res.data["firewall_policies"]
    assert len(pols) == 1
    assert pols[0]["name"] == "Allow-Web"
    assert pols[0]["action"] == "accept"

def test_fortinet_address_object():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    addrs = res.data["address_objects"]
    assert len(addrs) == 1
    assert addrs[0]["name"] == "Corp_Subnet"

def test_fortinet_static_route():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    routes = res.data["static_routes"]
    assert len(routes) == 1
    assert routes[0]["gateway"] == "10.0.0.254"

def test_fortinet_ntp():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    assert res.data["ntp"]["servers"] == ["10.10.10.10"]

def test_fortinet_vpn_recognition():
    res = FortinetParser().parse("CFG-004", FORTINET_FULL_CONFIG, "Firewall")
    assert res.data["vpn"]["configured"] is True


# ── GENERAL & INFRASTRUCTURE TESTS ───────────────────────────────────────────

def test_unknown_vendor_not_parsed():
    res = parser_registry.parse_configuration("CFG-099", "Unknown", "Unknown", "random text")
    assert res.status == ParserStatusEnum.NOT_PARSED
    assert res.parser == "None"
    assert "outside the supported" in res.unsupported_reason

def test_unsupported_vendor_handled_safely():
    res = parser_registry.parse_configuration("CFG-100", "Huawei", "Switch", "sysname Huawei_SW")
    assert res.status == ParserStatusEnum.NOT_PARSED
    assert res.data == {}

def test_empty_configuration():
    res = CiscoParser().parse("CFG-101", "", "Switch")
    assert res.status == ParserStatusEnum.PARSED
    assert res.data["hostname"] is None

def test_malformed_configuration():
    res = CiscoParser().parse("CFG-102", "ASDFQWE123 !!! ### ::::", "Switch")
    assert res.status == ParserStatusEnum.PARSED

def test_evidence_source_line_numbers():
    res = CiscoParser().parse("CFG-001", CISCO_FULL_CONFIG, "Switch")
    assert len(res.evidence) >= 5
    for item in res.evidence:
        assert item.line > 0
        assert item.source == "parser"

def test_parser_registry_selection():
    assert isinstance(parser_registry.get_parser("CISCO"), CiscoParser)
    assert isinstance(parser_registry.get_parser("juniper"), JuniperParser)
    assert isinstance(parser_registry.get_parser("Fortinet"), FortinetParser)
    assert parser_registry.get_parser("NonExistent") is None


# ── API ENDPOINT INTEGRATION TESTS ───────────────────────────────────────────

def test_full_parse_api_flow():
    # 1. Upload config
    up_res = client.post(
        "/api/audits",
        files={"file": ("core_sw.cfg", io.BytesIO(CISCO_FULL_CONFIG.encode("utf-8")), "text/plain")},
        data={"framework": "CIS"},
    )
    assert up_res.status_code == 201
    audit_id = up_res.json()["audit_id"]

    # 2. Run detection
    det_res = client.post(f"/api/audits/{audit_id}/detect")
    assert det_res.status_code == 200

    # 3. Trigger parsing (POST /api/audits/{audit_id}/parse)
    parse_res = client.post(f"/api/audits/{audit_id}/parse")
    assert parse_res.status_code == 200
    summary = parse_res.json()

    assert summary["audit_id"] == audit_id
    assert summary["status"] == "PARSING_COMPLETE"
    assert summary["total_files"] == 1
    assert summary["parsed_files"] == 1

    parsed_file = summary["files"][0]
    assert parsed_file["status"] == "PARSED"
    assert parsed_file["parser"] == "CiscoParser"
    assert parsed_file["data"]["hostname"] == "CORE-SW-01"

    # 4. Get parsing summary (GET /api/audits/{audit_id}/parsing)
    get_parse_res = client.get(f"/api/audits/{audit_id}/parsing")
    assert get_parse_res.status_code == 200
    assert get_parse_res.json()["audit_id"] == audit_id

    # 5. Get file parsing (GET /api/audits/{audit_id}/parsing/{file_id})
    file_id = parsed_file["file_id"]
    file_parse_res = client.get(f"/api/audits/{audit_id}/parsing/{file_id}")
    assert file_parse_res.status_code == 200
    assert file_parse_res.json()["data"]["hostname"] == "CORE-SW-01"


def test_parse_missing_audit():
    res = client.post("/api/audits/AUD-NONEXISTENT/parse")
    assert res.status_code == 404


def test_parse_without_detection():
    # Upload config but do NOT run detection
    up_res = client.post(
        "/api/audits",
        files={"file": ("cisco.cfg", io.BytesIO(CISCO_FULL_CONFIG.encode("utf-8")), "text/plain")},
        data={"framework": "CIS"},
    )
    audit_id = up_res.json()["audit_id"]

    # Parse directly without detection -> 400 error
    parse_res = client.post(f"/api/audits/{audit_id}/parse")
    assert parse_res.status_code == 400
    assert "detection" in parse_res.json()["detail"].lower()
