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

Core Workflow

Ingest → Detect → Parse → Normalize → Assess → Find → Remediate → Report

Ingestion — Processes individual configuration files or ZIP archives and generates metadata, hashes, and inventory.
Detection — Identifies vendor and device type using deterministic pattern matching and weighted evidence scoring.
Parsing — Extracts security-relevant configuration from Cisco, Juniper, and Fortinet devices.
AI Understanding — Assists with unfamiliar/unknown vendor syntax through structured extraction and evidence validation.
Normalization — Converts vendor-specific data into a vendor-neutral security model.
Compliance — Evaluates normalized configurations using deterministic CIS, NIST, and DISA STIG-oriented controls.
Findings — Generates evidence-backed findings for failed controls and limitations for unverifiable controls.
Remediation — Produces vendor-specific configuration proposals with validation and rollback guidance.
Reporting — Generates persistent HTML/PDF audit snapshots and stores audit history in PostgreSQL.
AI Safety Model

AI is advisory, not authoritative.

AI → Configuration Understanding
AI → Evidence Interpretation
AI → Security Explanation

Deterministic Engine → Compliance Decision
Human → Remediation Validation

AI cannot directly determine compliance, modify severity, fabricate evidence, or execute remediation.

Sensitive values such as passwords, PSKs, SNMP communities, and private keys are redacted before AI processing.

Low-confidence AI interpretation requires manual validation.

Compliance Model

N-CASA uses three assessment states:

Result	Meaning
PASS	Evidence proves the control is satisfied
FAIL	Evidence proves the control is violated
NOT_VERIFIABLE	Evidence is insufficient for a reliable decision

This prevents unsupported configurations from being incorrectly marked compliant.

Supported Vendors
Cisco
Juniper
Fortinet
Unknown / AI-assisted
Security Frameworks
CIS Benchmarks
NIST SP 800-53
DISA Network Device STIGs
Key Technical Components
Frontend: React + Vite + Tailwind CSS
Backend: Python + FastAPI
Database: PostgreSQL
ORM: SQLAlchemy
Migrations: Alembic
Reporting: HTML / PDF
AI: Unknown-vendor understanding + security explanation
Security Principles
Evidence-first assessment
Deterministic compliance
Vendor-neutral normalization
Secret redaction
Human-in-the-loop validation
Proposal-only remediation
Persistent audit traceability
Validation
Backend Tests    : 174 Passed
Failures         : 0
Frontend Build   : Successful
Database         : PostgreSQL
Compliance       : Deterministic
Remediation      : Proposal-only
Reporting        : HTML + PDF
