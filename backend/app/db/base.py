"""
N-CASA Database Base Model
===========================
Declarative base class for SQLAlchemy 2.x ORM models.
"""

from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase


class Base(AsyncAttrs, DeclarativeBase):
    """Base model class for all SQLAlchemy ORM entities."""
    pass
