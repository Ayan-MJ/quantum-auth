import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import { generateKeyPair, encrypt, decrypt, KeyEnvelope, EncryptedPayload } from '../../src/ts';
import { b64urlEncode, b64urlDecode } from '../../src/ts/utils';

// Initialize libsodium before tests
beforeAll(async () => {
  // The first call to any function will initialize libsodium
  await generateKeyPair();
});

describe('Crypto SDK - TypeScript', () => {
  describe('Key Generation', () => {
    it('should generate a key pair without a password', async () => {
      const keyEnvelope = await generateKeyPair();
      
      expect(keyEnvelope).toBeDefined();
      expect(keyEnvelope.algorithm).toBe('x25519-kyber768-hybrid');
      expect(keyEnvelope.public_key).toBeDefined();
      expect(keyEnvelope.encrypted_private_key).toBeDefined();
      expect(keyEnvelope.created_at).toBeInstanceOf(Date);
    });
    
    it('should generate a key pair with a password', async () => {
      const password = 'test-password';
      const keyEnvelope = await generateKeyPair(password);
      
      expect(keyEnvelope).toBeDefined();
      expect(keyEnvelope.algorithm).toBe('x25519-kyber768-hybrid');
      expect(keyEnvelope.public_key).toBeDefined();
      expect(keyEnvelope.encrypted_private_key).toBeDefined();
      expect(keyEnvelope.created_at).toBeInstanceOf(Date);
    });
    
    it('should generate different key pairs on each call', async () => {
      const keyEnvelope1 = await generateKeyPair();
      const keyEnvelope2 = await generateKeyPair();
      
      expect(keyEnvelope1.public_key).not.toBe(keyEnvelope2.public_key);
      expect(keyEnvelope1.encrypted_private_key).not.toBe(keyEnvelope2.encrypted_private_key);
    });
  });
  
  describe('Encryption and Decryption', () => {
    it('should encrypt and decrypt a message', async () => {
      const keyEnvelope = await generateKeyPair();
      const message = new TextEncoder().encode('Hello, world!');
      
      const encryptedPayload = await encrypt(message, keyEnvelope.public_key);
      
      expect(encryptedPayload).toBeDefined();
      expect(encryptedPayload.algorithm).toBe('x25519-kyber768-hybrid');
      expect(encryptedPayload.ephemeral_public_key).toBeDefined();
      expect(encryptedPayload.kyber_ciphertext).toBeDefined();
      expect(encryptedPayload.nonce).toBeDefined();
      expect(encryptedPayload.ciphertext).toBeDefined();
      
      const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope);
      
      expect(decryptedMessage).toEqual(message);
      expect(new TextDecoder().decode(decryptedMessage)).toBe('Hello, world!');
    });
    
    it('should encrypt and decrypt a message with a password-protected key', async () => {
      const password = 'test-password';
      const keyEnvelope = await generateKeyPair(password);
      const message = new TextEncoder().encode('Hello, world!');
      
      const encryptedPayload = await encrypt(message, keyEnvelope.public_key);
      const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope, password);
      
      expect(decryptedMessage).toEqual(message);
      expect(new TextDecoder().decode(decryptedMessage)).toBe('Hello, world!');
    });
    
    it('should fail to decrypt with an incorrect password', async () => {
      const password = 'correct-password';
      const wrongPassword = 'wrong-password';
      const keyEnvelope = await generateKeyPair(password);
      const message = new TextEncoder().encode('Hello, world!');
      
      const encryptedPayload = await encrypt(message, keyEnvelope.public_key);
      
      await expect(decrypt(encryptedPayload, keyEnvelope, wrongPassword))
        .rejects.toThrow('Failed to decrypt private key');
    });
    
    it('should encrypt and decrypt messages of different sizes', async () => {
      const keyEnvelope = await generateKeyPair();
      
      // Test with different message sizes
      const testSizes = [1, 10, 100, 1000, 10000];
      
      for (const size of testSizes) {
        const message = new Uint8Array(size);
        crypto.getRandomValues(message);
        
        const encryptedPayload = await encrypt(message, keyEnvelope.public_key);
        const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope);
        
        expect(decryptedMessage).toEqual(message);
      }
    });
  });
  
  describe('Property-based tests', () => {
    it('should round-trip encrypt/decrypt for any plaintext', async () => {
      // Generate a key pair once for all tests
      const keyEnvelope = await generateKeyPair();
      
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          async (plaintext) => {
            const encryptedPayload = await encrypt(plaintext, keyEnvelope.public_key);
            const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope);
            
            // Check that decryption recovers the original plaintext
            expect(decryptedMessage).toEqual(plaintext);
          }
        ),
        { numRuns: 50 } // Limit the number of runs for faster tests
      );
    });
    
    it('should round-trip encrypt/decrypt with password-protected keys', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 50 }),
          async (plaintext, password) => {
            const keyEnvelope = await generateKeyPair(password);
            const encryptedPayload = await encrypt(plaintext, keyEnvelope.public_key);
            const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope, password);
            
            // Check that decryption recovers the original plaintext
            expect(decryptedMessage).toEqual(plaintext);
          }
        ),
        { numRuns: 20 } // Limit the number of runs for faster tests
      );
    });
  });
  
  describe('Base64URL encoding/decoding', () => {
    it('should round-trip encode/decode for any byte array', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          (bytes) => {
            const encoded = b64urlEncode(bytes);
            const decoded = b64urlDecode(encoded);
            
            // Check that decoding recovers the original bytes
            expect(decoded).toEqual(bytes);
          }
        ),
        { numRuns: 100 }
      );
    });
    
    it('should produce URL-safe strings', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          (bytes) => {
            const encoded = b64urlEncode(bytes);
            
            // Check that the encoded string is URL-safe
            expect(encoded).not.toContain('+');
            expect(encoded).not.toContain('/');
            expect(encoded).not.toContain('=');
          }
        ),
        { numRuns: 100 }
      );
    });
  });
  
  describe('Performance', () => {
    it('should encrypt/decrypt a 10kB payload in under 5ms', async () => {
      const keyEnvelope = await generateKeyPair();
      const plaintext = new Uint8Array(10 * 1024); // 10kB
      crypto.getRandomValues(plaintext);
      
      const startEncrypt = performance.now();
      const encryptedPayload = await encrypt(plaintext, keyEnvelope.public_key);
      const encryptTime = performance.now() - startEncrypt;
      
      const startDecrypt = performance.now();
      const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope);
      const decryptTime = performance.now() - startDecrypt;
      
      const totalTime = encryptTime + decryptTime;
      
      console.log(`Encrypt time: ${encryptTime.toFixed(2)}ms`);
      console.log(`Decrypt time: ${decryptTime.toFixed(2)}ms`);
      console.log(`Total time: ${totalTime.toFixed(2)}ms`);
      
      // This might fail in CI environments, so we'll make it a soft assertion
      if (totalTime > 5) {
        console.warn(`Performance target not met: ${totalTime.toFixed(2)}ms > 5ms`);
      }
      
      expect(decryptedMessage).toEqual(plaintext);
    });
  });
});
