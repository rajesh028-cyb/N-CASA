"""
Unit and Integration Tests for Block 7: Deterministic Compliance Engine
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.compliance import (
    compliance_engine,
    compliance_rule_registry,
    ComplianceStatusEnum,
    ComplianceSeverityEnum,
    get_catalog_controls,
)
from app.normalization.models import (
    NormalizationStatusEnum,
    NormalizedACL,
    NormalizedACLRule,
    NormalizedAuthentication,
    NormalizedConfiguration,
    NormalizedEvidenceItem,
    NormalizedFirewallPolicy,
    NormalizedHTTP,
    NormalizedHTTPS,
    NormalizedIdentity,
    NormalizedInterface,
    NormalizedLogging,
    NormalizedManagement,
    NormalizedNTP,
    NormalizedRouting,
    NormalizedSSH,
    NormalizedSecurityZone,
    NormalizedTelnet,
    NormalizedVPN,
)

client = TestClient(app)

# ─────────────────────────────────────────────────────────────────────────────
# Sample Mock Normalized Configurations for Unit Testing
# ─────────────────────────────────────────────────────────────────────────────

def create_sample_normalized_config(
    hostname="CORE-SW-01",
    ssh_enabled=True,
    ssh_version="2",
    telnet_enabled=False,
    http_enabled=False,
    https_enabled=True,
    enable_secret=True,
    aaa_enabled=True,
    remote_logging=True,
    ntp_configured=True,
    has_disabled_iface=True,
    routing_configured=True,
    fw_policies_explicit=True,
    acl_explicit=True,
    vpn_configured=True,
) -> NormalizedConfiguration:
    return NormalizedConfiguration(
        file_id="test_device.cfg",
        vendor="Cisco",
        device_type="ROUTER",
        status=NormalizationStatusEnum.NORMALIZED,
        normalizer="CiscoNormalizer",
        identity=NormalizedIdentity(hostname=hostname),
        management=NormalizedManagement(
            ssh=NormalizedSSH(enabled=ssh_enabled, version=ssh_version),
            telnet=NormalizedTelnet(enabled=telnet_enabled),
            http=NormalizedHTTP(enabled=http_enabled),
            https=NormalizedHTTPS(enabled=https_enabled),
        ),
        authentication=NormalizedAuthentication(
            enable_secret_present=enable_secret,
            aaa_enabled=aaa_enabled,
        ),
        interfaces=[
            NormalizedInterface(name="Gi0/1", enabled=True, ip_addresses=["192.168.1.1/24"]),
            NormalizedInterface(name="Gi0/2", enabled=False if has_disabled_iface else True, ip_addresses=[]),
        ],
        routing=NormalizedRouting(
            static_routes=[{"destination": "0.0.0.0/0", "next_hop": "192.168.1.254"}] if routing_configured else [],
            ospf_configured=routing_configured,
        ),
        acls=[
            NormalizedACL(
                name="SECURE_ACL",
                rules=[NormalizedACLRule(action="permit" if acl_explicit else None, protocol="ip")]
            )
        ] if acl_explicit is not None else [],
        firewall_policies=[
            NormalizedFirewallPolicy(
                id="pol1",
                name="allow_trust",
                action="ACCEPT" if fw_policies_explicit else None,
            )
        ] if fw_policies_explicit is not None else [],
        security_zones=[NormalizedSecurityZone(name="trust", interfaces=["Gi0/1"])],
        logging=NormalizedLogging(
            enabled=remote_logging,
            remote_servers=["10.10.10.50"] if remote_logging else [],
        ),
        ntp=NormalizedNTP(
            servers=["10.10.10.1"] if ntp_configured else [],
        ),
        vpn=NormalizedVPN(
            configured=vpn_configured,
            types=["IPsec"] if vpn_configured else [],
            tunnels=["tunnel1"] if vpn_configured else [],
        ),
        evidence=[
            NormalizedEvidenceItem(
                field="management.ssh",
                value="2",
                source_vendor="Cisco",
                source_file="test_device.cfg",
                source_line=45,
                source_text="ip ssh version 2",
            ),
            NormalizedEvidenceItem(
                field="hostname",
                value=hostname,
                source_vendor="Cisco",
                source_file="test_device.cfg",
                source_line=10,
                source_text=f"hostname {hostname}",
            ),
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Registry & Catalog Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_rule_registry_loads_all_rules():
    rules = compliance_rule_registry.get_rules()
    assert len(rules) == 13

def test_catalog_controls():
    controls = get_catalog_controls()
    assert len(controls) == 13
    cis_controls = get_catalog_controls("CIS")
    assert len(cis_controls) == 8
    nist_controls = get_catalog_controls("NIST")
    assert len(nist_controls) == 4
    stig_controls = get_catalog_controls("STIG")
    assert len(stig_controls) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 2. Individual Rule Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_rule_ssh():
    rule = compliance_rule_registry.get_rule("CIS-NET-SSH-001")
    assert rule is not None

    # SSH v2 -> PASS
    cfg_pass = create_sample_normalized_config(ssh_enabled=True, ssh_version="2")
    res_pass = rule.evaluate(cfg_pass)
    assert res_pass.status == ComplianceStatusEnum.PASS
    assert len(res_pass.evidence) > 0

    # SSH v1 -> FAIL
    cfg_fail = create_sample_normalized_config(ssh_enabled=True, ssh_version="1")
    res_fail = rule.evaluate(cfg_fail)
    assert res_fail.status == ComplianceStatusEnum.FAIL

    # SSH disabled / unknown -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(ssh_enabled=None, ssh_version=None)
    res_unk = rule.evaluate(cfg_unk)
    assert res_unk.status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_telnet():
    rule = compliance_rule_registry.get_rule("CIS-NET-TELNET-001")

    # Telnet enabled -> FAIL
    cfg_fail = create_sample_normalized_config(telnet_enabled=True)
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL

    # Telnet disabled -> PASS
    cfg_pass = create_sample_normalized_config(telnet_enabled=False)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # Telnet unknown -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(telnet_enabled=None)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_http():
    rule = compliance_rule_registry.get_rule("CIS-NET-HTTP-001")

    # HTTP enabled -> FAIL
    cfg_fail = create_sample_normalized_config(http_enabled=True)
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL

    # HTTP disabled -> PASS
    cfg_pass = create_sample_normalized_config(http_enabled=False)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # HTTP unknown -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(http_enabled=None)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_https():
    rule = compliance_rule_registry.get_rule("CIS-NET-HTTPS-001")

    # HTTPS enabled -> PASS
    cfg_pass = create_sample_normalized_config(https_enabled=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # HTTPS unknown/disabled -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(https_enabled=None)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_aaa():
    rule = compliance_rule_registry.get_rule("NIST-NET-AUTH-001")

    # AAA enabled -> PASS
    cfg_pass = create_sample_normalized_config(enable_secret=True, aaa_enabled=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # AAA explicitly disabled -> FAIL
    cfg_fail = create_sample_normalized_config(enable_secret=False, aaa_enabled=False)
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL

    # AAA unknown -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(enable_secret=None, aaa_enabled=None)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_logging():
    rule = compliance_rule_registry.get_rule("NIST-NET-LOG-001")

    # Remote logging configured -> PASS
    cfg_pass = create_sample_normalized_config(remote_logging=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # Logging explicitly disabled -> FAIL
    cfg_fail = create_sample_normalized_config(remote_logging=False)
    # Note: remote_logging=False sets enabled=False
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL


def test_rule_ntp():
    rule = compliance_rule_registry.get_rule("NIST-NET-NTP-001")

    # NTP configured -> PASS
    cfg_pass = create_sample_normalized_config(ntp_configured=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # NTP unavailable -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(ntp_configured=False)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_hostname():
    rule = compliance_rule_registry.get_rule("CIS-NET-ID-001")

    # Valid hostname -> PASS
    cfg_pass = create_sample_normalized_config(hostname="CORE-ROUTER-01")
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # Default hostname -> FAIL
    cfg_fail = create_sample_normalized_config(hostname="Router")
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL

    # Missing hostname -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(hostname=None)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_interface_state():
    rule = compliance_rule_registry.get_rule("CIS-NET-IFACE-001")

    # Has disabled interface -> PASS
    cfg_pass = create_sample_normalized_config(has_disabled_iface=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # Unverified / all active -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(has_disabled_iface=False)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_firewall_policy():
    rule = compliance_rule_registry.get_rule("CIS-NET-FW-001")

    # Explicit action -> PASS
    cfg_pass = create_sample_normalized_config(fw_policies_explicit=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # Missing action -> FAIL
    cfg_fail = create_sample_normalized_config(fw_policies_explicit=False)
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL


def test_rule_acl():
    rule = compliance_rule_registry.get_rule("CIS-NET-ACL-001")

    # Explicit action -> PASS
    cfg_pass = create_sample_normalized_config(acl_explicit=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # Missing action -> FAIL
    cfg_fail = create_sample_normalized_config(acl_explicit=False)
    assert rule.evaluate(cfg_fail).status == ComplianceStatusEnum.FAIL


def test_rule_routing():
    rule = compliance_rule_registry.get_rule("STIG-NET-ROUTING-001")

    # Visible routing -> PASS
    cfg_pass = create_sample_normalized_config(routing_configured=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # No routing info -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(routing_configured=False)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


def test_rule_vpn():
    rule = compliance_rule_registry.get_rule("NIST-NET-VPN-001")

    # VPN visible -> PASS
    cfg_pass = create_sample_normalized_config(vpn_configured=True)
    assert rule.evaluate(cfg_pass).status == ComplianceStatusEnum.PASS

    # No VPN -> NOT_VERIFIABLE
    cfg_unk = create_sample_normalized_config(vpn_configured=False)
    assert rule.evaluate(cfg_unk).status == ComplianceStatusEnum.NOT_VERIFIABLE


# ─────────────────────────────────────────────────────────────────────────────
# 3. Engine & Framework Filtering Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_engine_evaluation_summary_counts():
    cfg = create_sample_normalized_config()
    summary = compliance_engine.evaluate_configurations("audit-123", [cfg])

    assert summary.audit_id == "audit-123"
    assert summary.status == "COMPLIANCE_COMPLETE"
    assert summary.summary.total_controls == 13
    assert summary.summary.passed + summary.summary.failed + summary.summary.not_verifiable == 13
    assert len(summary.results) == 13


def test_engine_framework_filtering():
    cfg = create_sample_normalized_config()
    cis_summary = compliance_engine.evaluate_configurations("audit-123", [cfg], framework_filter="CIS")

    assert cis_summary.summary.total_controls == 8
    assert all(r.framework == "CIS" for r in cis_summary.results)


# ─────────────────────────────────────────────────────────────────────────────
# 4. API Endpoints Integration Test Workflow
# ─────────────────────────────────────────────────────────────────────────────

CISCO_CONFIG = """!
hostname CORE-ROUTER-01
enable secret 5 $1$mER7$j1Q5cQ
username admin privilege 15 secret 5 $1$mER7$j1Q5cQ
!
interface GigabitEthernet0/1
 description Uplink Interface
 ip address 192.168.1.1 255.255.255.0
!
interface GigabitEthernet0/2
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


def test_compliance_api_workflow():
    # 1. Upload audit
    content = CISCO_CONFIG.encode("utf-8")
    response = client.post(
        "/api/audits",
        files={"file": ("cisco_comp_test.cfg", io.BytesIO(content), "text/plain")},
        data={"framework": "CIS"},
    )
    assert response.status_code == 201
    audit_id = response.json()["audit_id"]

    # 2. Ingest, Detect, Parse, Normalize
    client.post(f"/api/audits/{audit_id}/ingest")
    client.post(f"/api/audits/{audit_id}/detect")
    client.post(f"/api/audits/{audit_id}/parse")
    client.post(f"/api/audits/{audit_id}/normalize")

    # 3. POST /api/audits/{audit_id}/compliance
    comp_resp = client.post(f"/api/audits/{audit_id}/compliance")
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()
    assert comp_data["status"] == "COMPLIANCE_COMPLETE"
    assert comp_data["summary"]["total_controls"] == 13

    # 4. GET /api/audits/{audit_id}/compliance
    get_comp = client.get(f"/api/audits/{audit_id}/compliance")
    assert get_comp.status_code == 200
    get_data = get_comp.json()
    assert len(get_data["results"]) == 13

    # 5. GET /api/audits/{audit_id}/compliance?framework=CIS
    get_cis = client.get(f"/api/audits/{audit_id}/compliance?framework=CIS")
    assert get_cis.status_code == 200
    assert len(get_cis.json()["results"]) == 8

    # 6. GET /api/audits/{audit_id}/compliance/CIS-NET-SSH-001
    get_control = client.get(f"/api/audits/{audit_id}/compliance/CIS-NET-SSH-001")
    assert get_control.status_code == 200
    c_res = get_control.json()
    assert c_res["control_id"] == "CIS-NET-SSH-001"
    assert c_res["status"] == "PASS"

    # 7. GET non-existent control
    get_missing_control = client.get(f"/api/audits/{audit_id}/compliance/INVALID-001")
    assert get_missing_control.status_code == 404


def test_compliance_error_handling():
    # Non-existent audit -> 404
    resp = client.post("/api/audits/non-existent-audit/compliance")
    assert resp.status_code == 404

    # Audit without normalization -> 400
    content = b"hostname router\n"
    up_resp = client.post(
        "/api/audits",
        files={"file": ("no_norm.cfg", io.BytesIO(content), "text/plain")},
        data={"framework": "CIS"},
    )
    assert up_resp.status_code == 201
    audit_id = up_resp.json()["audit_id"]

    comp_err = client.post(f"/api/audits/{audit_id}/compliance")
    assert comp_err.status_code == 400
