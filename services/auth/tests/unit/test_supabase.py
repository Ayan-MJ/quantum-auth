"""
Unit tests for Supabase JWT verification
"""
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException
from jose import jwt

from app.core.supabase import JWKSCache, TokenPayload, verify_token


class TestJWKSCache:
    """Test JWKS cache"""
    
    @pytest.mark.asyncio
    async def test_get_jwks_fresh(self):
        """Test getting JWKS when cache is empty"""
        # Mock response
        mock_jwks = {"keys": [{"kid": "test-kid", "kty": "RSA"}]}
        
        # Mock httpx client
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = MagicMock()
        
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get.return_value = mock_response
        
        # Create cache instance
        cache = JWKSCache()
        
        # Test with mocked client
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await cache.get_jwks()
        
        # Verify result
        assert result == mock_jwks
        assert cache.jwks == mock_jwks
        assert cache.last_updated is not None
    
    @pytest.mark.asyncio
    async def test_get_jwks_cached(self):
        """Test getting JWKS when cache is not expired"""
        # Create cache instance with pre-populated cache
        cache = JWKSCache()
        cache.jwks = {"keys": [{"kid": "test-kid", "kty": "RSA"}]}
        cache.last_updated = time.time()
        
        # Mock httpx client (should not be called)
        mock_client = AsyncMock()
        
        # Test with mocked client
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await cache.get_jwks()
        
        # Verify result
        assert result == cache.jwks
        assert mock_client.__aenter__.called is False
    
    @pytest.mark.asyncio
    async def test_get_jwks_expired(self):
        """Test getting JWKS when cache is expired"""
        # Create cache instance with expired cache
        cache = JWKSCache()
        cache.jwks = {"keys": [{"kid": "old-kid", "kty": "RSA"}]}
        cache.last_updated = time.time() - (cache.cache_time + 10)  # Expired
        
        # Mock response with new data
        mock_jwks = {"keys": [{"kid": "new-kid", "kty": "RSA"}]}
        
        # Mock httpx client
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = MagicMock()
        
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get.return_value = mock_response
        
        # Test with mocked client
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await cache.get_jwks()
        
        # Verify result
        assert result == mock_jwks
        assert cache.jwks == mock_jwks
        assert cache.last_updated is not None
    
    @pytest.mark.asyncio
    async def test_get_jwks_error_with_fallback(self):
        """Test getting JWKS with error but with cached fallback"""
        # Create cache instance with cached data
        cache = JWKSCache()
        cache.jwks = {"keys": [{"kid": "fallback-kid", "kty": "RSA"}]}
        cache.last_updated = time.time() - (cache.cache_time + 10)  # Expired
        
        # Mock httpx client that raises an error
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get.side_effect = httpx.HTTPError("Connection error")
        
        # Test with mocked client
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await cache.get_jwks()
        
        # Verify fallback to cached result
        assert result == cache.jwks
    
    @pytest.mark.asyncio
    async def test_get_jwks_error_no_fallback(self):
        """Test getting JWKS with error and no cached fallback"""
        # Create cache instance with no cached data
        cache = JWKSCache()
        cache.jwks = None
        cache.last_updated = None
        
        # Mock httpx client that raises an error
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get.side_effect = httpx.HTTPError("Connection error")
        
        # Test with mocked client
        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(HTTPException) as excinfo:
                await cache.get_jwks()
        
        # Verify exception
        assert excinfo.value.status_code == 503
        assert "Could not fetch JWKS" in str(excinfo.value.detail)


class TestVerifyToken:
    """Test token verification"""
    
    @pytest.mark.asyncio
    async def test_verify_token_valid(self):
        """Test verifying a valid token"""
        # Create a test key
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Convert to JWK
        public_numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "kid": "test-kid",
            "n": str(public_numbers.n),
            "e": str(public_numbers.e),
        }
        
        # Mock JWKS
        mock_jwks = {"keys": [jwk]}
        
        # Create token payload
        payload = {
            "sub": "user-123",
            "exp": int(time.time()) + 3600,  # 1 hour from now
            "aud": "authenticated",
            "iss": "https://your-project.supabase.co/auth/v1",
            "email": "user@example.com",
        }
        
        # Create token
        token = jwt.encode(payload, key=private_key, algorithm="RS256", headers={"kid": "test-kid"})
        
        # Mock JWKS cache
        mock_cache = AsyncMock()
        mock_cache.get_jwks.return_value = mock_jwks
        
        # Test with mocked cache and JWT decode
        with patch("app.core.supabase.jwks_cache", mock_cache):
            with patch("jose.jwt.decode", return_value=payload):
                result = await verify_token(token)
        
        # Verify result
        assert isinstance(result, TokenPayload)
        assert result.sub == payload["sub"]
        assert result.exp == payload["exp"]
        assert result.aud == payload["aud"]
        assert result.iss == payload["iss"]
        assert result.email == payload["email"]
    
    @pytest.mark.asyncio
    async def test_verify_token_invalid(self):
        """Test verifying an invalid token"""
        # Mock JWKS
        mock_jwks = {"keys": [{"kid": "test-kid", "kty": "RSA"}]}
        
        # Create an invalid token
        token = "invalid.token.here"
        
        # Mock JWKS cache
        mock_cache = AsyncMock()
        mock_cache.get_jwks.return_value = mock_jwks
        
        # Test with mocked cache and JWT decode that raises an error
        with patch("app.core.supabase.jwks_cache", mock_cache):
            with patch("jose.jwt.get_unverified_header", return_value={"kid": "test-kid"}):
                with patch("jose.jwt.decode", side_effect=jwt.JWTError("Invalid token")):
                    with pytest.raises(HTTPException) as excinfo:
                        await verify_token(token)
        
        # Verify exception
        assert excinfo.value.status_code == 401
        assert "Invalid token" in str(excinfo.value.detail)
    
    @pytest.mark.asyncio
    async def test_verify_token_key_not_found(self):
        """Test verifying a token with a key that doesn't exist in JWKS"""
        # Mock JWKS with no matching key
        mock_jwks = {"keys": [{"kid": "other-kid", "kty": "RSA"}]}
        
        # Create token with different kid
        token = "header.payload.signature"
        
        # Mock JWKS cache
        mock_cache = AsyncMock()
        mock_cache.get_jwks.return_value = mock_jwks
        
        # Test with mocked cache and JWT header
        with patch("app.core.supabase.jwks_cache", mock_cache):
            with patch("jose.jwt.get_unverified_header", return_value={"kid": "test-kid"}):
                with pytest.raises(HTTPException) as excinfo:
                    await verify_token(token)
        
        # Verify exception
        assert excinfo.value.status_code == 401
        assert "Key not found" in str(excinfo.value.detail)
