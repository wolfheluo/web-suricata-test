"""Shared pytest fixtures for the Suricata Web test suite."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import AsyncMock, patch

from app.config import settings
from app.database import get_db
from app.main import app
from app.models.base import Base
from app.models.user import User
from app.routers.auth import pwd_context, create_access_token

# Use SQLite for tests (async via aiosqlite)
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def db_session():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with TestSessionLocal() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(db_session: AsyncSession):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        id=str(uuid.uuid4()),
        username="testuser",
        hashed_password=pwd_context.hash("testpass123"),
        role="admin",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User) -> dict[str, str]:
    token = create_access_token(test_user.id, test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def valid_pcap_le_bytes() -> bytes:
    """pcap little-endian magic bytes."""
    return b"\xd4\xc3\xb2\xa1"


@pytest.fixture
def valid_pcap_be_bytes() -> bytes:
    """pcap big-endian magic bytes."""
    return b"\xa1\xb2\xc3\xd4"


@pytest.fixture
def valid_pcapng_bytes() -> bytes:
    """pcapng magic bytes."""
    return b"\x0a\x0d\x0d\x0a"


@pytest.fixture
def analysis_summary_with_large_conn() -> dict:
    """Summary with a single connection > 100 MB."""
    return {
        "top_ip": [
            {
                "connection": "1.2.3.4:80 -> 5.6.7.8:443",
                "bytes": 110 * 1024 * 1024,
            }
        ],
        "event": {},
        "geo": {},
    }


@pytest.fixture
def analysis_summary_normal() -> dict:
    """Summary with no anomalies."""
    return {
        "top_ip": [
            {"connection": "10.0.0.1:80 -> 10.0.0.2:443", "bytes": 1024}
        ],
        "event": {
            "HTTP": {"count": 50},
            "TLS": {"count": 30},
            "DNS": {"count": 20},
        },
        "geo": {"TW": 7000, "US": 2000, "LOCAL": 1000},
    }
