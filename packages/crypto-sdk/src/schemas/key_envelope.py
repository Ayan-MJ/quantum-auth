from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class KeyEnvelope(BaseModel):
    """
    Envelope containing cryptographic key material for hybrid X25519-Kyber768 encryption.
    
    Attributes:
        algorithm: The cryptographic algorithm used, always "x25519-kyber768-hybrid"
        public_key: Base64url-encoded public key material
        encrypted_private_key: Base64url-encoded encrypted private key material
        created_at: Timestamp when the key was created
    """
    algorithm: Literal["x25519-kyber768-hybrid"] = "x25519-kyber768-hybrid"
    public_key: str = Field(description="Base64url-encoded public key material")
    encrypted_private_key: str = Field(description="Base64url-encoded encrypted private key material")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EncryptedPayload(BaseModel):
    """
    Container for encrypted data using hybrid X25519-Kyber768 encryption.
    
    Attributes:
        algorithm: The cryptographic algorithm used, always "x25519-kyber768-hybrid"
        ephemeral_public_key: Base64url-encoded ephemeral public key used for this encryption
        kyber_ciphertext: Base64url-encoded Kyber768 ciphertext
        nonce: Base64url-encoded nonce used for symmetric encryption
        ciphertext: Base64url-encoded encrypted data
    """
    algorithm: Literal["x25519-kyber768-hybrid"] = "x25519-kyber768-hybrid"
    ephemeral_public_key: str = Field(description="Base64url-encoded ephemeral public key")
    kyber_ciphertext: str = Field(description="Base64url-encoded Kyber768 ciphertext")
    nonce: str = Field(description="Base64url-encoded nonce")
    ciphertext: str = Field(description="Base64url-encoded encrypted data")
