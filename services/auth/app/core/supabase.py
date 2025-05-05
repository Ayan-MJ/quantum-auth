"""
Supabase JWT verification utilities
"""
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union

import httpx
from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwk, jwt
from jose.utils import base64url_decode
from pydantic import BaseModel

from app.core.config import settings


class JWKSCache:
    """
    Cache for JWKS (JSON Web Key Set) to avoid frequent HTTP requests
    """
    def __init__(self):
        self.jwks: Optional[Dict] = None
        self.last_updated: Optional[float] = None
        self.cache_time: int = settings.JWKS_CACHE_TIME  # 24 hours in seconds

    async def get_jwks(self) -> Dict:
        """
        Get JWKS from cache or fetch from Supabase
        """
        current_time = time.time()
        
        # If cache is empty or expired, fetch new JWKS
        if (
            self.jwks is None 
            or self.last_updated is None 
            or current_time - self.last_updated > self.cache_time
        ):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(settings.SUPABASE_JWKS_URL)
                    response.raise_for_status()
                    self.jwks = response.json()
                    self.last_updated = current_time
            except httpx.HTTPError as e:
                # If fetching fails and we have a cached version, use it
                if self.jwks is not None:
                    return self.jwks
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Could not fetch JWKS: {str(e)}",
                )
        
        return self.jwks


# Create global JWKS cache instance
jwks_cache = JWKSCache()


class TokenPayload(BaseModel):
    """
    JWT token payload model
    """
    sub: str
    exp: int
    aud: Union[str, List[str]]
    iss: str
    email: Optional[str] = None


async def verify_token(token: str) -> TokenPayload:
    """
    Verify JWT token and return payload
    """
    try:
        # Get the JWKS
        jwks = await jwks_cache.get_jwks()
        
        # Get the token header
        header = jwt.get_unverified_header(token)
        
        # Find the key that matches the kid in the token header
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == header.get("kid"):
                rsa_key = key
                break
        
        if not rsa_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Key not found",
            )
        
        # Verify the token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        
        return TokenPayload(**payload)
    
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )


async def get_current_user(request: Request) -> TokenPayload:
    """
    Dependency to get the current authenticated user from JWT token
    """
    # Get the token from the Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token missing",
        )
    
    token = auth_header.split(" ")[1]
    
    # Verify the token and return the payload
    return await verify_token(token)


def get_user_id_from_token(token_payload: TokenPayload = Depends(get_current_user)) -> str:
    """
    Extract user ID from token payload
    """
    return token_payload.sub
