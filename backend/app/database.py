"""
RansomShield Backend — Database Configuration & Session Management

Provides the async SQLAlchemy engine, session factory, and base model class
for PostgreSQL. Uses asyncpg as the async driver for high-throughput
WebSocket telemetry ingestion.

Configuration is loaded from environment variables with sensible defaults
for local development. In production, these should be set via a .env file
or container orchestration secrets.

Connection pool sizing:
    - pool_size=20:      Handles 20 concurrent DB writes (one per agent event).
    - max_overflow=10:   Allows bursting to 30 connections during ransomware
                         storms (multiple agents detecting simultaneously).
    - pool_recycle=3600: Recycles connections every hour to avoid PostgreSQL
                         idle connection timeouts.
"""

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


# ─────────────────────────────────────────────────────────────────────────────
# Database URL Configuration
# ─────────────────────────────────────────────────────────────────────────────
# Format: postgresql+asyncpg://user:password@host:port/dbname
#
# Components loaded from environment variables:
#   POSTGRES_USER     — Database user (default: ransomshield)
#   POSTGRES_PASSWORD — Database password (default: ransomshield_dev)
#   POSTGRES_HOST     — Database host (default: localhost)
#   POSTGRES_PORT     — Database port (default: 5432)
#   POSTGRES_DB       — Database name (default: ransomshield)
#
# The full URL can also be overridden with DATABASE_URL.
# Fetch variables with their correct default fallbacks
DB_USER = os.getenv("POSTGRES_USER", "postgres") # Changed from 'postgresql' to 'postgres'
DB_PASS = os.getenv("POSTGRES_PASSWORD", "yamini123") # Enter the password you reset it to
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "postgres")

# Construct the URL using an f-string
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)


# ─────────────────────────────────────────────────────────────────────────────
# Async Engine
# ─────────────────────────────────────────────────────────────────────────────
# The engine manages the connection pool to PostgreSQL. We use asyncpg as
# the async driver because it's the fastest Python PostgreSQL driver
# (2-3x faster than psycopg2 for bulk inserts).

engine = create_async_engine(
    DATABASE_URL,
    # ── Connection Pool Tuning ────────────────────────────────────────────
    pool_size=20,        # Base pool: 20 persistent connections.
    max_overflow=10,     # Burst capacity: up to 30 total connections.
    pool_recycle=3600,   # Recycle connections every hour (avoids PG timeouts).
    pool_pre_ping=True,  # Verify connection liveness before checkout.
    # ── Logging ───────────────────────────────────────────────────────────
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",  # SQL logging toggle.
)


# ─────────────────────────────────────────────────────────────────────────────
# Async Session Factory
# ─────────────────────────────────────────────────────────────────────────────
# Each request/WebSocket message gets its own session. Sessions are:
#   - Scoped to a single unit of work (one telemetry event = one session).
#   - Automatically rolled back on exception (expire_on_commit=False
#     allows reading attributes after commit without re-fetching).

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ─────────────────────────────────────────────────────────────────────────────
# Declarative Base
# ─────────────────────────────────────────────────────────────────────────────
# All SQLAlchemy models inherit from this base. Using the modern
# DeclarativeBase (SQLAlchemy 2.0 style) instead of the legacy
# declarative_base() factory.


class Base(DeclarativeBase):
    """Base class for all RansomShield ORM models."""

    pass


# ─────────────────────────────────────────────────────────────────────────────
# Dependency: Database Session
# ─────────────────────────────────────────────────────────────────────────────
# FastAPI dependency that provides a scoped async session. Usage:
#   async def endpoint(db: AsyncSession = Depends(get_db)):


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields an async database session and ensures proper cleanup.

    Usage as a FastAPI dependency:
        @app.get("/events")
        async def list_events(db: AsyncSession = Depends(get_db)):
            ...

    The session is committed on success and rolled back on exception.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

