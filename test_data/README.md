# N-CASA Test Data Packages

This directory contains standalone multi-vendor network device configuration files and test ZIP bundles used for automated validation and manual compliance audits.

## Directory Layout
- `01_cisco/`: Hardened Cisco IOS router configuration (`cisco_router_secure.cfg`)
- `02_cisco/`: Insecure Cisco IOS router configuration (`cisco_router_insecure.cfg`)
- `03_juniper/`: Juniper Junos OS configuration (`juniper_firewall.cfg`)
- `04_fortinet/`: Fortinet FortiOS firewall configuration (`fortigate_firewall.conf`)
- `05_unknown/`: Generic / custom network configuration (`unknown_vendor.conf`)
- `N-CASA_Manual_Test_Configs.zip`: Multi-device archive package containing all test configs for end-to-end audit testing.
