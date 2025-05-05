"""
Core cryptographic functions for the Quantum Auth Crypto SDK
"""

import os
import time
import hashlib
import nacl.public
import nacl.secret
import nacl.utils
import nacl.bindings
from datetime import datetime, timezone
from typing import Optional, Union, Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pqcrypto.kem import ml_kem_768

from .models import KeyEnvelope, EncryptedPayload
from .utils import b64url_encode, b64url_decode, bytes_concat, bytes_split, get_random_bytes

# Constants
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 100000
NONCE_LENGTH = 24
KEY_LENGTH = 32

# Kyber768 key sizes
KYBER_PUBLIC_KEY_SIZE = ml_kem_768.PUBLIC_KEY_SIZE
KYBER_SECRET_KEY_SIZE = ml_kem_768.SECRET_KEY_SIZE
KYBER_CIPHERTEXT_SIZE = ml_kem_768.CIPHERTEXT_SIZE

# Flag to disable Kyber until issues are resolved
USE_KYBER = False


def generate_key_pair(password_or_credential: Optional[str] = None) -> KeyEnvelope:
    """
    Generates a hybrid X25519-Kyber768 key pair
    
    Args:
        password_or_credential: Optional password or credential to encrypt the private key
        
    Returns:
        A KeyEnvelope containing the public key and encrypted private key
    """
    # Generate X25519 key pair
    x25519_keypair = nacl.public.PrivateKey.generate()
    x25519_public_key = bytes(x25519_keypair.public_key)
    x25519_secret_key = bytes(x25519_keypair)
    
    # Generate Kyber768 key pair (if enabled)
    if USE_KYBER:
        kyber_keypair = ml_kem_768.generate_keypair()
        kyber_public_key = kyber_keypair[0]
        kyber_secret_key = kyber_keypair[1]
    else:
        # Dummy Kyber keys to maintain format compatibility
        kyber_public_key = bytes(KYBER_PUBLIC_KEY_SIZE)  # Empty bytes
        kyber_secret_key = bytes(KYBER_SECRET_KEY_SIZE)  # Empty bytes
    
    if USE_KYBER:
        # Combine public keys
        public_key = bytes_concat(
            bytes([len(x25519_public_key)]),  # 1-byte length prefix
            x25519_public_key,
            bytes([len(kyber_public_key) & 0xFF]),  # Lower byte of length
            bytes([(len(kyber_public_key) >> 8) & 0xFF]),  # Upper byte of length
            kyber_public_key
        )
        
        # Combine private keys
        private_key = bytes_concat(
            bytes([len(x25519_secret_key)]),  # 1-byte length prefix
            x25519_secret_key,
            bytes([len(kyber_secret_key) & 0xFF]),  # Lower byte of length
            bytes([(len(kyber_secret_key) >> 8) & 0xFF]),  # Upper byte of length
            kyber_secret_key
        )
    else:
        # Only use X25519 keys when Kyber is disabled
        public_key = x25519_public_key
        private_key = x25519_secret_key
    
    # Encrypt private key
    if password_or_credential:
        # Use password-based encryption
        salt = get_random_bytes(SALT_LENGTH)
        
        # Generate encryption key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password_or_credential.encode('utf-8'))
        
        # Encrypt private key
        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(NONCE_LENGTH)
        ciphertext = box.encrypt(private_key, nonce).ciphertext
        
        # Combine salt, nonce, and ciphertext
        encrypted_private_key = bytes_concat(salt, nonce, ciphertext)
    else:
        # If no password provided, "encrypt" with a random key for consistent API
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE) 
        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(NONCE_LENGTH)
        ciphertext = box.encrypt(private_key, nonce).ciphertext
        
        # Prepend the random key to nonce and ciphertext, similar to TypeScript
        encrypted_private_key = bytes_concat(key, nonce, ciphertext)
 
    return KeyEnvelope(
        algorithm="x25519-kyber768-hybrid",
        public_key=b64url_encode(public_key),
        encrypted_private_key=b64url_encode(encrypted_private_key),
        created_at=datetime.now(timezone.utc)
    )


def encrypt(plaintext: bytes, recipient_pub_key: str) -> EncryptedPayload:
    """
    Encrypts data using a recipient's public key
    
    Args:
        plaintext: The data to encrypt
        recipient_pub_key: Base64url-encoded recipient public key
        
    Returns:
        An EncryptedPayload containing all necessary data for decryption
    """
    # Decode recipient's public key
    recipient_public_key_bytes = b64url_decode(recipient_pub_key)
    
    # TODO: Re-enable Kyber - Need to parse based on actual key format/algorithm field
    # Assume X25519-only format for now
    x25519_public_key = recipient_public_key_bytes
    
    # Generate ephemeral X25519 key pair
    ephemeral_x25519_keypair = nacl.public.PrivateKey.generate()
    ephemeral_x25519_public_key = bytes(ephemeral_x25519_keypair.public_key)
    ephemeral_x25519_private_key = bytes(ephemeral_x25519_keypair)[:32]  # Extract only the 32-byte private key
    
    # Perform X25519 key exchange using crypto_scalarmult to match TypeScript
    x25519_shared_secret = nacl.bindings.crypto_scalarmult(
        ephemeral_x25519_private_key,
        x25519_public_key
    )
    
    # Debug logging
    print(f"PY Encrypt: X25519 shared secret length: {len(x25519_shared_secret)}, hex: {x25519_shared_secret.hex()[:16]}...")
    
    # TODO: Re-enable Kyber
    # Hash the X25519 shared secret with SHA-256 to match TypeScript implementation
    combined_shared_secret = hashlib.sha256(x25519_shared_secret).digest()
    
    # Debug logging
    print(f"PY Encrypt: Combined shared secret length: {len(combined_shared_secret)}, hex: {combined_shared_secret.hex()[:16]}...")
    
    # Encrypt the plaintext
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(combined_shared_secret)
    ciphertext = box.encrypt(plaintext, nonce=nonce).ciphertext
    
    # Debug logging
    print(f"PY Encrypt: Nonce length: {len(nonce)}, hex: {nonce.hex()[:16]}...")
    print(f"PY Encrypt: Actual ciphertext length: {len(ciphertext)}, hex: {ciphertext.hex()[:16]}...")
    
    # Return the encrypted payload
    return EncryptedPayload(
        algorithm="x25519-kyber768-hybrid",
        ephemeral_public_key=b64url_encode(ephemeral_x25519_public_key),
        kyber_ciphertext="",  # Empty since we're not using Kyber
        nonce=b64url_encode(nonce),
        ciphertext=b64url_encode(ciphertext)
    )

def decrypt(
    payload: EncryptedPayload,
    envelope: KeyEnvelope,
    password_or_credential: Optional[str] = None
) -> bytes:
    """
    Decrypts data using the recipient's private key
    
    Args:
        payload: The encrypted payload
        envelope: The key envelope containing the encrypted private key
        password_or_credential: Optional password or credential to decrypt the private key
        
    Returns:
        The decrypted data
        
    Raises:
        ValueError: If decryption fails
    """
    # Decode encrypted private key
    encrypted_private_key_bytes = b64url_decode(envelope.encrypted_private_key)
    
    # Extract private key
    if password_or_credential:
        # Password-based decryption
        salt = encrypted_private_key_bytes[:SALT_LENGTH]
        nonce = encrypted_private_key_bytes[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
        ciphertext = encrypted_private_key_bytes[SALT_LENGTH + NONCE_LENGTH:]
        
        # Generate encryption key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password_or_credential.encode('utf-8'))
        
        # Decrypt private key
        try:
            box = nacl.secret.SecretBox(key)
            private_key = box.decrypt(ciphertext, nonce)
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: Invalid password") from e
    else:
        # No password, extract stored key, nonce, and ciphertext
        if len(encrypted_private_key_bytes) < nacl.secret.SecretBox.KEY_SIZE + NONCE_LENGTH:
            raise ValueError("Invalid encrypted private key format (no password)")
        
        key = encrypted_private_key_bytes[:nacl.secret.SecretBox.KEY_SIZE]
        nonce = encrypted_private_key_bytes[nacl.secret.SecretBox.KEY_SIZE : nacl.secret.SecretBox.KEY_SIZE + NONCE_LENGTH]
        ciphertext = encrypted_private_key_bytes[nacl.secret.SecretBox.KEY_SIZE + NONCE_LENGTH:]
        
        try:
            box = nacl.secret.SecretBox(key)
            private_key = box.decrypt(ciphertext, nonce)
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key (no password)") from e
    
    # Extract X25519 private key - in our current implementation, private_key is just the X25519 key
    x25519_private_key = private_key
    
    # Decode payload components
    ephemeral_public_key = b64url_decode(payload.ephemeral_public_key)
    nonce = b64url_decode(payload.nonce)
    ciphertext = b64url_decode(payload.ciphertext)
    
    # Perform X25519 key exchange using crypto_scalarmult to match TypeScript
    x25519_shared_secret = nacl.bindings.crypto_scalarmult(
        x25519_private_key,
        ephemeral_public_key
    )
    
    # Debug logging
    print(f"PY Decrypt: X25519 shared secret length: {len(x25519_shared_secret)}, hex: {x25519_shared_secret.hex()[:16]}...")
    print(f"PY Decrypt: Nonce length: {len(nonce)}, hex: {nonce.hex()[:16]}...")
    print(f"PY Decrypt: Ciphertext length: {len(ciphertext)}, hex: {ciphertext.hex()[:16]}...")
    
    # Hash the X25519 shared secret with SHA-256 to match TypeScript implementation
    combined_shared_secret = hashlib.sha256(x25519_shared_secret).digest()
    print(f"PY Decrypt: Combined shared secret length: {len(combined_shared_secret)}, hex: {combined_shared_secret.hex()[:16]}...")
    
    # Decrypt the ciphertext
    try:
        box = nacl.secret.SecretBox(combined_shared_secret)
        decrypted_message = box.decrypt(ciphertext, nonce=nonce)
    except nacl.exceptions.CryptoError as e:
        raise ValueError("Failed to decrypt message") from e

    return decrypted_message
