N-CASA MANUAL TEST CONFIGURATION PACK
======================================

Purpose:
Use these configuration files to manually test the N-CASA audit pipeline.

Folders:
01_cisco/
    Cisco configuration expected to contain mostly secure settings.

02_cisco/
    Cisco configuration intentionally containing insecure settings.
    Useful for testing FAIL findings and remediation proposals.

03_juniper/
    Juniper configuration for deterministic Juniper parsing.

04_fortinet/
    Fortinet configuration for deterministic Fortinet parsing.

05_unknown/
    Deliberately unfamiliar syntax for testing the unknown-vendor path.

Suggested manual test order:
1. Upload 01_cisco/cisco_router_secure.cfg
2. Upload 02_cisco/cisco_router_insecure.cfg
3. Upload 03_juniper/juniper_firewall.cfg
4. Upload 04_fortinet/fortigate_firewall.conf
5. Upload 05_unknown/unknown_vendor.conf

Important:
- These are synthetic lab configurations.
- IP addresses use documentation/test ranges.
- No real network device should be connected to these files.
- The unknown-vendor file is intentionally synthetic and is not intended to represent a real vendor.
- N-CASA remediation must remain proposal-only; do not execute generated commands on a device.

What to verify for each audit:
- Ingestion
- Vendor/device detection
- Vendor-specific parsing
- Normalization
- CIS/NIST/STIG compliance
- PASS / FAIL / NOT_VERIFIABLE results
- Findings
- Remediation proposals
- AI-assisted path for the unknown vendor
- Report generation
- Dashboard persistence after refresh/restart
