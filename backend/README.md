# N-CASA Backend — Block 2

**Network Configuration Automated Security Auditor — FastAPI Backend**

## Overview

Block 2 implements the configuration upload pipeline:

```
React Frontend
     ↓  POST /api/audits (multipart)
FastAPI Backend
     ↓
File Validation (extension + size)
     ↓
Safe Local Storage  →  storage/uploads/<AUDIT_ID>/
     ↓
In-Memory Metadata Store
     ↓
Audit ID Returned to Frontend
```

## Requirements

- Python 3.11+
- pip

## Setup

```bash
cd backend/
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --reload
```

Server starts at: http://127.0.0.1:8000

## API Documentation

- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc:      http://127.0.0.1:8000/redoc

## Endpoints

| Method | Path                     | Description                   |
|--------|--------------------------|-------------------------------|
| GET    | /api/health              | Health check                  |
| POST   | /api/audits              | Upload configuration          |
| GET    | /api/audits              | List all audits               |
| GET    | /api/audits/{audit_id}   | Get single audit              |

## Tests

```bash
cd backend/
pytest tests/ -v
```

## Accepted File Types

| Extension | Description               |
|-----------|---------------------------|
| .cfg      | Cisco / general config    |
| .conf     | Generic config            |
| .txt      | Plain text config         |
| .zip      | Bundled config archive    |

## File Size Limit

50 MB maximum per upload.

## Security Notes (Block 2)

- File extension is validated server-side (never trusted from client).
- Filenames are sanitised to prevent path traversal.
- Uploaded files are NOT executed, parsed, or extracted.
- ZIP files are stored as-is (extraction in Block 3).
- Audit IDs are generated server-side (UUID-based).
- CORS is configured for localhost:5173 only.

## Block Architecture

```
Block 2  ← YOU ARE HERE
Block 3  → Configuration Ingestion / ZIP Extraction
Block 4  → Vendor & Device Detection
Block 5  → Vendor Parsers
Block 6  → Normalization
Block 7  → Compliance Engine
Block 8  → Findings + Evidence
Block 9  → Remediation Engine
Block 10 → AI Unknown-Vendor Understanding
Block 11 → PostgreSQL + Full Audit History
Block 12 → Report Generation
Block 13 → Final SIH UI/UX + Integration
```
