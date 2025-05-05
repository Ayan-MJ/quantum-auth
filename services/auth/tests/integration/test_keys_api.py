"""
Integration tests for key management API endpoints
"""
import json
import uuid
from unittest.mock import patch

import pytest
from fastapi import status
from httpx import AsyncClient

from app.schemas.keys import KeyEnvelope


@pytest.mark.asyncio
class TestKeysAPI:
    """Test key management API endpoints"""
    
    async def test_create_key(self, client: AsyncClient, mock_verify_token):
        """Test creating a new key for a user"""
        # Test data
        key_data = {
            "algorithm": "x25519-kyber768-hybrid",
            "public_key": "mock-public-key",
            "encrypted_private_key": "mock-encrypted-private-key"
        }
        
        # Mock the database query and insert
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            response = await client.post(
                "/api/v1/keys",
                headers={"Authorization": "Bearer mock_token"},
                json=key_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["algorithm"] == key_data["algorithm"]
        assert data["public_key"] == key_data["public_key"]
        assert data["encrypted_private_key"] == key_data["encrypted_private_key"]
    
    async def test_create_key_existing(self, client: AsyncClient, mock_verify_token):
        """Test creating a key for a user that already has one"""
        # Test data
        key_data = {
            "algorithm": "x25519-kyber768-hybrid",
            "public_key": "new-public-key",
            "encrypted_private_key": "new-encrypted-private-key"
        }
        
        # Mock the database query to return an existing key
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            # Create a mock existing key
            mock_key = {
                "user_id": "user-123",
                "algorithm": "x25519-kyber768-hybrid",
                "public_key": "existing-public-key",
                "encrypted_private_key": "existing-encrypted-private-key",
            }
            mock_execute.return_value.scalar_one_or_none.return_value = mock_key
            
            response = await client.post(
                "/api/v1/keys",
                headers={"Authorization": "Bearer mock_token"},
                json=key_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_409_CONFLICT
        data = response.json()
        assert "already exists" in data["detail"]
    
    async def test_get_key(self, client: AsyncClient, mock_verify_token):
        """Test getting a user's key"""
        # Mock the database query to return a key
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            # Create a mock key
            mock_key = {
                "user_id": "user-123",
                "algorithm": "x25519-kyber768-hybrid",
                "public_key": "mock-public-key",
                "encrypted_private_key": "mock-encrypted-private-key",
                "created_at": "2025-05-05T00:00:00"
            }
            mock_execute.return_value.scalar_one_or_none.return_value = mock_key
            
            response = await client.get(
                "/api/v1/keys",
                headers={"Authorization": "Bearer mock_token"}
            )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["algorithm"] == mock_key["algorithm"]
        assert data["public_key"] == mock_key["public_key"]
        assert data["encrypted_private_key"] == mock_key["encrypted_private_key"]
    
    async def test_get_key_not_found(self, client: AsyncClient, mock_verify_token):
        """Test getting a key for a user that doesn't have one"""
        # Mock the database query to return None
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            response = await client.get(
                "/api/v1/keys",
                headers={"Authorization": "Bearer mock_token"}
            )
        
        # Verify response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "not found" in data["detail"]
    
    async def test_update_key(self, client: AsyncClient, mock_verify_token):
        """Test updating a user's key"""
        # Test data
        key_data = {
            "algorithm": "x25519-kyber768-hybrid",
            "public_key": "updated-public-key",
            "encrypted_private_key": "updated-encrypted-private-key"
        }
        
        # Mock the database query and update
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            # Create a mock existing key
            mock_key = {
                "user_id": "user-123",
                "algorithm": "x25519-kyber768-hybrid",
                "public_key": "old-public-key",
                "encrypted_private_key": "old-encrypted-private-key",
            }
            mock_execute.return_value.scalar_one_or_none.return_value = mock_key
            
            response = await client.put(
                "/api/v1/keys",
                headers={"Authorization": "Bearer mock_token"},
                json=key_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["algorithm"] == key_data["algorithm"]
        assert data["public_key"] == key_data["public_key"]
        assert data["encrypted_private_key"] == key_data["encrypted_private_key"]
    
    async def test_update_key_not_found(self, client: AsyncClient, mock_verify_token):
        """Test updating a key for a user that doesn't have one"""
        # Test data
        key_data = {
            "algorithm": "x25519-kyber768-hybrid",
            "public_key": "updated-public-key",
            "encrypted_private_key": "updated-encrypted-private-key"
        }
        
        # Mock the database query to return None
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            response = await client.put(
                "/api/v1/keys",
                headers={"Authorization": "Bearer mock_token"},
                json=key_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "not found" in data["detail"]
