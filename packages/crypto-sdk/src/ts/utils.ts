/**
 * Utility functions for the crypto-sdk
 */

/**
 * Encodes a Uint8Array to a base64url string
 * @param bytes The bytes to encode
 * @returns A base64url encoded string
 */
export function b64urlEncode(bytes: Uint8Array): string {
  // Convert to base64
  let base64 = btoa(String.fromCharCode(...bytes));
  // Convert to base64url (replace + with -, / with _, and remove trailing =)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a base64url string to a Uint8Array
 * @param str The base64url string to decode
 * @returns The decoded bytes
 */
export function b64urlDecode(str: string): Uint8Array {
  // Convert from base64url to base64 (add padding if needed)
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  const paddedBase64 = padding ? base64 + '='.repeat(4 - padding) : base64;
  
  // Decode base64 to bytes
  const binaryString = atob(paddedBase64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Concatenates multiple Uint8Arrays into a single Uint8Array
 * @param arrays The arrays to concatenate
 * @returns A new Uint8Array containing all the input arrays
 */
export function bytesConcat(...arrays: Uint8Array[]): Uint8Array {
  // Calculate total length
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  
  // Create a new array with the total length
  const result = new Uint8Array(totalLength);
  
  // Copy each array into the result
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  
  return result;
}

/**
 * Splits a Uint8Array into multiple parts at specified lengths
 * @param bytes The bytes to split
 * @param lengths The lengths of each part
 * @returns An array of Uint8Arrays
 * @throws Error if the sum of lengths doesn't match the bytes length
 */
export function bytesSplit(bytes: Uint8Array, ...lengths: number[]): Uint8Array[] {
  const totalLength = lengths.reduce((acc, length) => acc + length, 0);
  if (totalLength !== bytes.length) {
    throw new Error(`Sum of lengths (${totalLength}) doesn't match bytes length (${bytes.length})`);
  }
  
  const result: Uint8Array[] = [];
  let offset = 0;
  
  for (const length of lengths) {
    result.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  
  return result;
}

/**
 * Generates cryptographically secure random bytes
 * @param length The number of bytes to generate
 * @returns A Uint8Array of random bytes
 */
export function getRandomBytes(length: number): Uint8Array {
  // Use Web Crypto API if available
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    return window.crypto.getRandomValues(new Uint8Array(length));
  }
  
  // Node.js fallback
  if (typeof require !== 'undefined') {
    try {
      const crypto = require('crypto');
      return new Uint8Array(crypto.randomBytes(length));
    } catch (e) {
      throw new Error('No secure random source available');
    }
  }
  
  throw new Error('No secure random source available');
}
