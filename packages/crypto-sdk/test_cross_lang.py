#!/usr/bin/env python
"""
Simplified cross-language test for the Quantum Auth Crypto SDK
"""
import os
import json
import base64
import subprocess
from pathlib import Path

from src.py.crypto import generate_key_pair, encrypt, decrypt
from src.py.models import KeyEnvelope, EncryptedPayload

def test_python_to_ts():
    """Test Python encryption to TypeScript decryption"""
    print("\n=== Testing Python encryption to TypeScript decryption ===")
    
    # Generate a key pair in Python
    key_envelope = generate_key_pair()
    print(f"Generated Python key pair with public key: {key_envelope.public_key[:16]}...")
    
    # Encrypt a message in Python
    message = b"Hello from Python to TypeScript!"
    encrypted_payload = encrypt(message, key_envelope.public_key)
    print(f"Encrypted message in Python. Ciphertext: {encrypted_payload.ciphertext[:16]}...")
    
    # Save the key envelope and encrypted payload to files
    key_envelope_dict = key_envelope.model_dump()
    key_envelope_dict['created_at'] = key_envelope_dict['created_at'].isoformat()
    
    with open('py_key.json', 'w') as f:
        json.dump(key_envelope_dict, f)
    
    with open('py_payload.json', 'w') as f:
        json.dump(encrypted_payload.model_dump(), f)
    
    # Create a Node.js script to decrypt
    node_script = """
    const fs = require('fs');
    const { decrypt } = require('./dist/index');
    
    async function main() {
        try {
            const keyEnvelope = JSON.parse(fs.readFileSync('py_key.json', 'utf8'));
            const encryptedPayload = JSON.parse(fs.readFileSync('py_payload.json', 'utf8'));
            
            console.log(`TS received key with public key: ${keyEnvelope.public_key.substring(0, 16)}...`);
            console.log(`TS received payload with ciphertext: ${encryptedPayload.ciphertext.substring(0, 16)}...`);
            
            const decryptedBytes = await decrypt(encryptedPayload, keyEnvelope);
            const decryptedText = new TextDecoder().decode(decryptedBytes);
            console.log(`TS successfully decrypted: "${decryptedText}"`);
            return true;
        } catch (error) {
            console.error('Decryption failed:', error);
            return false;
        }
    }
    
    main().then(success => process.exit(success ? 0 : 1));
    """
    
    with open('decrypt_test.js', 'w') as f:
        f.write(node_script)
    
    # Run the Node.js script
    result = subprocess.run(
        ['node', 'decrypt_test.js'],
        cwd=os.path.abspath(Path(__file__).parent),
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print(f"Error: {result.stderr}")
    
    return result.returncode == 0

def test_ts_to_python():
    """Test TypeScript encryption to Python decryption"""
    print("\n=== Testing TypeScript encryption to Python decryption ===")
    
    # Create a Node.js script to generate a key and encrypt
    node_script = """
    const fs = require('fs');
    const { generateKeyPair, encrypt } = require('./dist/index');
    
    async function main() {
        try {
            const keyEnvelope = await generateKeyPair();
            const message = new TextEncoder().encode('Hello from TypeScript to Python!');
            const encryptedPayload = await encrypt(message, keyEnvelope.public_key);
            
            console.log(`TS generated key with public key: ${keyEnvelope.public_key.substring(0, 16)}...`);
            console.log(`TS encrypted message with ciphertext: ${encryptedPayload.ciphertext.substring(0, 16)}...`);
            
            fs.writeFileSync('ts_key.json', JSON.stringify(keyEnvelope));
            fs.writeFileSync('ts_payload.json', JSON.stringify(encryptedPayload));
            return true;
        } catch (error) {
            console.error('Encryption failed:', error);
            return false;
        }
    }
    
    main().then(success => process.exit(success ? 0 : 1));
    """
    
    with open('encrypt_test.js', 'w') as f:
        f.write(node_script)
    
    # Run the Node.js script
    result = subprocess.run(
        ['node', 'encrypt_test.js'],
        cwd=os.path.abspath(Path(__file__).parent),
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print(f"Error: {result.stderr}")
    
    if result.returncode != 0:
        return False
    
    # Load the key and payload from files
    with open('ts_key.json', 'r') as f:
        key_envelope_dict = json.load(f)
    
    with open('ts_payload.json', 'r') as f:
        encrypted_payload_dict = json.load(f)
    
    # Convert to Python objects
    if isinstance(key_envelope_dict.get('created_at'), str):
        key_envelope_dict['created_at'] = key_envelope_dict['created_at']
    
    key_envelope = KeyEnvelope(**key_envelope_dict)
    encrypted_payload = EncryptedPayload(**encrypted_payload_dict)
    
    print(f"Python received key with public key: {key_envelope.public_key[:16]}...")
    print(f"Python received payload with ciphertext: {encrypted_payload.ciphertext[:16]}...")
    
    # Decrypt in Python
    try:
        decrypted_message = decrypt(encrypted_payload, key_envelope)
        print(f"Python successfully decrypted: \"{decrypted_message.decode('utf-8')}\"")
        return True
    except Exception as e:
        print(f"Python decryption failed: {e}")
        return False

def main():
    # Build the TypeScript package first
    print("Building TypeScript package...")
    subprocess.run(['npm', 'run', 'build'], 
                  cwd=os.path.abspath(Path(__file__).parent), 
                  check=True,
                  capture_output=True)
    
    # Run the tests
    py_to_ts_success = test_python_to_ts()
    ts_to_py_success = test_ts_to_python()
    
    if py_to_ts_success and ts_to_py_success:
        print("\n✅ All cross-language tests passed!")
        return 0
    else:
        print("\n❌ Cross-language tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())
