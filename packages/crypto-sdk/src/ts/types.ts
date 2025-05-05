/**
 * Type definitions for the Quantum Auth Crypto SDK
 */

/**
 * Envelope containing cryptographic key material for hybrid X25519-Kyber768 encryption
 */
export interface KeyEnvelope {
  /**
   * The cryptographic algorithm used, always "x25519-kyber768-hybrid"
   */
  algorithm: "x25519-kyber768-hybrid";
  
  /**
   * Base64url-encoded public key material
   */
  public_key: string;
  
  /**
   * Base64url-encoded encrypted private key material
   */
  encrypted_private_key: string;
  
  /**
   * Timestamp when the key was created
   */
  created_at: Date;
}

/**
 * Container for encrypted data using hybrid X25519-Kyber768 encryption
 */
export interface EncryptedPayload {
  /**
   * The cryptographic algorithm used, always "x25519-kyber768-hybrid"
   */
  algorithm: "x25519-kyber768-hybrid";
  
  /**
   * Base64url-encoded ephemeral public key used for this encryption
   */
  ephemeral_public_key: string;
  
  /**
   * Base64url-encoded Kyber768 ciphertext
   */
  kyber_ciphertext: string;
  
  /**
   * Base64url-encoded nonce used for symmetric encryption
   */
  nonce: string;
  
  /**
   * Base64url-encoded encrypted data
   */
  ciphertext: string;
}
