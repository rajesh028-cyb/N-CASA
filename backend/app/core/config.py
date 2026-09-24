"""
N-CASA Backend — Core Configuration
====================================
Settings are loaded from environment variables.
Use a .env file in the backend/ directory for local development.

Block 2: temporary in-memory storage only.
Block 11: replace with PostgreSQL settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "N-CASA API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # ── CORS ─────────────────────────────────────────────────────
    # Comma-separated list of allowed origins.
    # In production this should be the real frontend URL.
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # ── Upload limits ─────────────────────────────────────────────
    MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024   # 50 MB
    ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".zip", ".cfg", ".conf", ".txt"})

    # ── Storage ───────────────────────────────────────────────────
    # Relative to the backend/ working directory at runtime.
    # Block 11: replace with cloud/DB storage path.
    STORAGE_DIR: str = "storage"
    UPLOAD_DIR: str = "storage/uploads"
    REPORTS_DIR: str = "storage/reports"

    # ── API prefix ────────────────────────────────────────────────
    API_PREFIX: str = "/api"

    # ── AI Configuration (Block 10) ───────────────────────────────
    AI_ENABLED: bool = False
    AI_PROVIDER: str = "mock"
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_KEY: str = ""
    AI_BASE_URL: str = ""
    AI_TIMEOUT_SECONDS: int = 60

    # ── Database Configuration (Block 11) ─────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/n_casa"
    TEST_DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/n_casa_test"


settings = Settings()
