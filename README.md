# N-CASA — Network Configuration Automated Security Auditor

N-CASA is an AI-assisted, multi-vendor network configuration security and compliance auditing platform. It analyzes configuration files from heterogeneous network environments, normalizes vendor-specific configurations into a common security model, evaluates them against deterministic security controls, and generates evidence-backed findings, remediation proposals, and audit reports.

## Architecture

```text
Configuration Files / ZIP
          │
          ▼
   ┌───────────────┐
   │   Ingestion   │
   │ Inventory +   │
   │ SHA-256 Hash  │
   └───────┬───────┘
           ▼
   ┌───────────────────┐
   │ Vendor Detection  │
   │ Cisco / Juniper /  │
   │ Fortinet / Unknown │
   └─────────┬─────────┘
             │
       ┌─────┴─────┐
       ▼           ▼
 Known Vendor   Unknown Vendor
       │           │
       ▼           ▼
 Deterministic   AI-Assisted
    Parser       Understanding
       │           │
       └─────┬─────┘
             ▼
   ┌──────────────────┐
   │   Normalization  │
   │ Vendor-Neutral   │
   │ Security Model   │
   └────────┬─────────┘
            ▼
   ┌──────────────────┐
   │ Deterministic    │
   │ Compliance Engine│
   │ CIS / NIST / STIG│
   └────────┬─────────┘
            ▼
     PASS / FAIL /
    NOT_VERIFIABLE
            │
            ▼
   ┌──────────────────┐
   │ Findings Engine  │
   │ Evidence + Risk  │
   └────────┬─────────┘
            ▼
   ┌──────────────────┐
   │ Remediation      │
   │ Proposal Engine  │
   └────────┬─────────┘
            ▼
      Human Review
            │
            ▼
   ┌──────────────────┐
   │ Report Snapshot  │
   │ HTML / PDF       │
   └────────┬─────────┘
            ▼
       PostgreSQL
