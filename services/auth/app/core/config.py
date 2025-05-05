"""
Configuration settings for the Auth service
"""
import os
from typing import List, Optional, Union

from pydantic import AnyHttpUrl, PostgresDsn, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings
    """
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Quantum Auth API"
    
    # CORS settings
    ALLOWED_ORIGINS: Union[str, List[str]] = os.environ.get("ALLOWED_ORIGINS", "*")
    
    # Database settings
    DATABASE_URL: PostgresDsn = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/quantum_auth"
    )
    
    # Supabase settings
    SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "https://your-project.supabase.co")
    SUPABASE_JWT_SECRET: Optional[str] = os.environ.get("SUPABASE_JWT_SECRET")
    SUPABASE_JWKS_URL: str = os.environ.get(
        "SUPABASE_JWKS_URL", 
        "https://your-project.supabase.co/.well-known/jwks.json"
    )
    JWT_AUDIENCE: str = os.environ.get("JWT_AUDIENCE", "authenticated")
    JWT_ISSUER: str = os.environ.get("JWT_ISSUER", "https://your-project.supabase.co/auth/v1")
    
    # Security settings
    JWKS_CACHE_TIME: int = 86400  # 24 hours in seconds
    
    # Shamir secret sharing settings
    DEFAULT_THRESHOLD: int = 3
    DEFAULT_SHARES: int = 5
    MAX_SHARES: int = 10
    
    @field_validator("ALLOWED_ORIGINS")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """
        Parse ALLOWED_ORIGINS into a list if it's a comma-separated string
        """
        if isinstance(v, str) and v != "*":
            return [origin.strip() for origin in v.split(",")]
        return v


# Create global settings instance
settings = Settings()
