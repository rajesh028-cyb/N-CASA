"""
Health check endpoint — N-CASA API & PostgreSQL Status
"""

import logging
from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text
from app.db.session import AsyncSessionLocal

logger = logging.getLogger("ncasa.routes.health")

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    database: str


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Returns the current health status of the N-CASA API and database connectivity.",
)
async def health_check() -> HealthResponse:
    db_status = "unavailable"
    overall_status = "degraded"

    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            db_status = "connected"
            overall_status = "healthy"
    except Exception as exc:
        logger.warning("Health check failed database connectivity: %s", exc)

    return HealthResponse(
        status=overall_status,
        service="n-casa-backend",
        database=db_status
    )
