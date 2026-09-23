"""
N-CASA FastAPI Application — Entry Point
==========================================
Run locally:

    cd backend/
    uvicorn app.main:app --reload

API documentation:
    http://127.0.0.1:8000/docs
    http://127.0.0.1:8000/redoc
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import health, audits, reports
from app.core.config import settings

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ncasa")


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("N-CASA API v%s starting up", settings.APP_VERSION)
    logger.info("CORS origins: %s", settings.CORS_ORIGINS)
    logger.info("Upload dir: %s", settings.UPLOAD_DIR)
    logger.info("Max upload: %d MB", settings.MAX_UPLOAD_BYTES // (1024 * 1024))
    yield
    # Shutdown
    logger.info("N-CASA API shutting down")


# ── FastAPI application ───────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "N-CASA — Network Configuration Automated Security Auditor\n\n"
        "Block 2: Configuration upload and audit job creation.\n"
        "Vendor detection, compliance analysis, and AI features are in later blocks."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allows the React dev server (localhost:5173) to call the API.
# Do NOT use allow_origins=["*"] — keep origins explicit and configurable.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router,  prefix=settings.API_PREFIX)
app.include_router(audits.router,  prefix=settings.API_PREFIX)
app.include_router(reports.router, prefix=settings.API_PREFIX)
