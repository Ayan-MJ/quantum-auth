"""
Key-related Pydantic schemas
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, UUID4


class KeyEnvelope(BaseModel):
    """
    Envelope containing cryptographic key material for hybrid X25519-Kyber768 encryption
    """
    algorithm: Literal["x25519-kyber768-hybrid"] = "x25519-kyber768-hybrid"
    public_key: str = Field(description="Base64url-encoded public key material")
    encrypted_private_key: str = Field(description="Base64url-encoded encrypted private key material")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        from_attributes = True


class KeyEnvelopeCreate(BaseModel):
    """
    Schema for creating a new key envelope
    """
    algorithm: Literal["x25519-kyber768-hybrid"] = "x25519-kyber768-hybrid"
    public_key: str = Field(description="Base64url-encoded public key material")
    encrypted_private_key: str = Field(description="Base64url-encoded encrypted private key material")


class KeyEnvelopeDB(KeyEnvelope):
    """
    Schema for key envelope in database
    """
    user_id: UUID4


class KeyEnvelopeResponse(KeyEnvelope):
    """
    Schema for key envelope response
    """
    user_id: UUID4
