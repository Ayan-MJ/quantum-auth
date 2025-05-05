"""
Pytest configuration file
"""
import asyncio
import os
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.models import Base
from app.db.session import get_db
from app.main import app

# Use an in-memory SQLite database for testing
TEST_DATABASE_URL = "sqlite:///:memory:"

# Create engine for tests
engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Set up the test database."""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    yield
    # Drop all tables
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    """Get a database session for tests."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db):
    """Get a test client for the FastAPI app."""
    # Override the get_db dependency
    def override_get_db():
        yield db
    
    app.dependency_overrides[get_db] = override_get_db
    
    # Create test client
    with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    # Clear dependency overrides
    app.dependency_overrides.clear()


@pytest.fixture
def mock_supabase_token():
    """Create a mock Supabase token for testing."""
    return {
        "sub": "user-123",
        "email": "test@example.com",
        "aud": "authenticated",
        "role": "authenticated",
        "exp": 1893456000,  # Far in the future
    }


@pytest.fixture
def mock_verify_token(monkeypatch, mock_supabase_token):
    """Mock the verify_token function."""
    from app.core.supabase import TokenPayload, verify_token
    
    async def mock_verify(*args, **kwargs):
        return TokenPayload(**mock_supabase_token)
    
    monkeypatch.setattr("app.core.supabase.verify_token", mock_verify)
