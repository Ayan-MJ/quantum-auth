"""
Integration tests for auth API endpoints
"""
import json
import uuid
from unittest.mock import patch

import pytest
from fastapi import status
from httpx import AsyncClient

from app.schemas.auth import SignupResponse


@pytest.mark.asyncio
class TestAuthAPI:
    """Test auth API endpoints"""
    
    async def test_signup_new_user(self, client: AsyncClient, mock_verify_token):
        """Test signup endpoint with a new user"""
        # Mock the database query to return None (no existing user)
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            response = await client.post(
                "/api/v1/auth/signup",
                headers={"Authorization": "Bearer mock_token"},
            )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user_id"] == "user-123"
        assert data["is_new"] is True
    
    async def test_signup_existing_user(self, client: AsyncClient, mock_verify_token):
        """Test signup endpoint with an existing user"""
        # Mock the database query to return an existing user
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            # Create a mock user record
            mock_user = {
                "user_id": "user-123",
                "algorithm": "x25519-kyber768-hybrid",
                "public_key": "mock-public-key",
                "encrypted_private_key": "mock-encrypted-private-key",
            }
            mock_execute.return_value.scalar_one_or_none.return_value = mock_user
            
            response = await client.post(
                "/api/v1/auth/signup",
                headers={"Authorization": "Bearer mock_token"},
            )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user_id"] == "user-123"
        assert data["is_new"] is False
    
    async def test_signup_invalid_token(self, client: AsyncClient):
        """Test signup endpoint with an invalid token"""
        # Don't mock verify_token, let it fail
        response = await client.post(
            "/api/v1/auth/signup",
            headers={"Authorization": "Bearer invalid_token"},
        )
        
        # Verify response
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_signup_missing_token(self, client: AsyncClient):
        """Test signup endpoint with a missing token"""
        response = await client.post("/api/v1/auth/signup")
        
        # Verify response
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
