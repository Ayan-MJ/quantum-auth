"""
Integration tests for recovery shares API endpoints
"""
import json
import uuid
from unittest.mock import patch

import pytest
from fastapi import status
from httpx import AsyncClient

from app.schemas.recovery import RecoveryShareCreate, RecoveryShareResponse


@pytest.mark.asyncio
class TestRecoveryAPI:
    """Test recovery shares API endpoints"""
    
    async def test_create_recovery_shares(self, client: AsyncClient, mock_verify_token):
        """Test creating recovery shares for a user"""
        # Test data
        recovery_data = {
            "threshold": 3,
            "num_shares": 5
        }
        
        # Mock the security module to return shares
        mock_shares = ["share1", "share2", "share3", "share4", "share5"]
        with patch("app.core.security.generate_secret_shares", return_value=mock_shares):
            # Mock the database query to return a key
            with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
                # Create a mock key
                mock_key = {
                    "user_id": "user-123",
                    "algorithm": "x25519-kyber768-hybrid",
                    "public_key": "mock-public-key",
                    "encrypted_private_key": "mock-encrypted-private-key",
                }
                mock_execute.return_value.scalar_one_or_none.return_value = mock_key
                
                response = await client.post(
                    "/api/v1/recovery/shares",
                    headers={"Authorization": "Bearer mock_token"},
                    json=recovery_data
                )
        
        # Verify response
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert len(data["shares"]) == recovery_data["num_shares"]
        assert data["threshold"] == recovery_data["threshold"]
        assert all(share in mock_shares for share in data["shares"])
    
    async def test_create_recovery_shares_no_key(self, client: AsyncClient, mock_verify_token):
        """Test creating recovery shares for a user without a key"""
        # Test data
        recovery_data = {
            "threshold": 3,
            "num_shares": 5
        }
        
        # Mock the database query to return None (no key)
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            response = await client.post(
                "/api/v1/recovery/shares",
                headers={"Authorization": "Bearer mock_token"},
                json=recovery_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "key not found" in data["detail"].lower()
    
    async def test_verify_recovery_shares_valid(self, client: AsyncClient):
        """Test verifying valid recovery shares"""
        # Test data
        verify_data = {
            "shares": ["share1", "share2", "share3"]
        }
        
        # Mock the security module to return True
        with patch("app.core.security.verify_shares", return_value=True):
            response = await client.post(
                "/api/v1/recovery/verify",
                json=verify_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is True
    
    async def test_verify_recovery_shares_invalid(self, client: AsyncClient):
        """Test verifying invalid recovery shares"""
        # Test data
        verify_data = {
            "shares": ["invalid1", "invalid2", "invalid3"]
        }
        
        # Mock the security module to return False
        with patch("app.core.security.verify_shares", return_value=False):
            response = await client.post(
                "/api/v1/recovery/verify",
                json=verify_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is False
    
    async def test_recover_key_valid(self, client: AsyncClient):
        """Test recovering a key with valid shares"""
        # Test data
        recover_data = {
            "shares": ["share1", "share2", "share3"],
            "user_id": "user-123"
        }
        
        # Mock the security module to return a secret
        mock_secret = "recovered-encrypted-private-key"
        with patch("app.core.security.recover_secret_from_shares", return_value=mock_secret):
            # Mock the database query to return a key
            with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
                # Create a mock key
                mock_key = {
                    "user_id": "user-123",
                    "algorithm": "x25519-kyber768-hybrid",
                    "public_key": "mock-public-key",
                    "encrypted_private_key": mock_secret,
                }
                mock_execute.return_value.scalar_one_or_none.return_value = mock_key
                
                response = await client.post(
                    "/api/v1/recovery/key",
                    json=recover_data
                )
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["algorithm"] == mock_key["algorithm"]
        assert data["public_key"] == mock_key["public_key"]
        assert data["encrypted_private_key"] == mock_secret
    
    async def test_recover_key_invalid_shares(self, client: AsyncClient):
        """Test recovering a key with invalid shares"""
        # Test data
        recover_data = {
            "shares": ["invalid1", "invalid2", "invalid3"],
            "user_id": "user-123"
        }
        
        # Mock the security module to raise an exception
        with patch("app.core.security.recover_secret_from_shares", side_effect=Exception("Invalid shares")):
            response = await client.post(
                "/api/v1/recovery/key",
                json=recover_data
            )
        
        # Verify response
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "invalid shares" in data["detail"].lower()
    
    async def test_recover_key_user_not_found(self, client: AsyncClient):
        """Test recovering a key for a user that doesn't exist"""
        # Test data
        recover_data = {
            "shares": ["share1", "share2", "share3"],
            "user_id": "nonexistent-user"
        }
        
        # Mock the security module to return a secret
        mock_secret = "recovered-encrypted-private-key"
        with patch("app.core.security.recover_secret_from_shares", return_value=mock_secret):
            # Mock the database query to return None (no key)
            with patch("sqlalchemy.ext.asyncio.AsyncSession.execute") as mock_execute:
                mock_execute.return_value.scalar_one_or_none.return_value = None
                
                response = await client.post(
                    "/api/v1/recovery/key",
                    json=recover_data
                )
        
        # Verify response
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "user not found" in data["detail"].lower()
