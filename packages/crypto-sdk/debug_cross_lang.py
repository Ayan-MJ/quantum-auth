#!/usr/bin/env python
"""
Debug script for cross-language encryption/decryption.
"""
import os
import json
import subprocess
import tempfile
from pathlib import Path

from src.py.crypto import generate_key_pair, encrypt
from src.py.models import KeyEnvelope, EncryptedPayload

def run_node_script(script_content):
    """Run a Node.js script and return its output."""
    with tempfile.NamedTemporaryFile(suffix='.mjs', delete=False) as temp:
        temp.write(script_content.encode('utf-8'))
        temp_path = temp.name

    try:
        result = subprocess.run(
            ['node', temp_path],
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        print(f"Node.js stdout: {result.stdout}")
        print(f"Node.js stderr: {result.stderr}")
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    finally:
        os.unlink(temp_path)

def main():
    print("=== DEBUGGING CROSS-LANGUAGE ENCRYPTION/DECRYPTION ===")
    
    # Generate a key pair in Python
    print("\n1. Generating key pair in Python...")
    key_envelope = generate_key_pair()
    print(f"Generated key pair with public key: {key_envelope.public_key[:16]}...")
    
    # Encrypt a message in Python
    print("\n2. Encrypting message in Python...")
    message = b"Hello from Python to Node.js!"
    encrypted_payload = encrypt(message, key_envelope.public_key)
    
    # Convert to serializable dictionaries
    key_envelope_dict = key_envelope.model_dump()
    # Convert datetime to ISO format string
    key_envelope_dict['created_at'] = key_envelope_dict['created_at'].isoformat()
    encrypted_payload_dict = encrypted_payload.model_dump()
    
    print("\n3. Python encryption result:")
    print(f"Ephemeral public key: {encrypted_payload.ephemeral_public_key[:16]}...")
    print(f"Nonce: {encrypted_payload.nonce[:16]}...")
    print(f"Ciphertext: {encrypted_payload.ciphertext[:16]}...")
    
    # Create a Node.js script to decrypt the message
    print("\n4. Attempting to decrypt in Node.js...")
    node_script = f"""
    import {{ decrypt }} from '{os.path.abspath(Path(__file__).parent)}/dist/index.mjs';
    import * as sodium from 'libsodium-wrappers-sumo';
    
    const keyEnvelope = {json.dumps(key_envelope_dict)};
    const encryptedPayload = {json.dumps(encrypted_payload_dict)};
    
    async function main() {{
        await sodium.ready;
        
        // Print private key details
        const privateKeyBytes = sodium.from_base64(keyEnvelope.private_key);
        console.log(`Node private key length: ${{privateKeyBytes.length}}, hex: ${{Buffer.from(privateKeyBytes).toString('hex').substring(0, 32)}}...`);
        
        // Print ephemeral public key details
        const ephemeralPublicKey = sodium.from_base64(encryptedPayload.ephemeral_public_key);
        console.log(`Node ephemeral public key length: ${{ephemeralPublicKey.length}}, hex: ${{Buffer.from(ephemeralPublicKey).toString('hex').substring(0, 32)}}...`);
        
        // Try to manually calculate the shared secret
        try {{
            const manualSharedSecret = sodium.crypto_scalarmult(privateKeyBytes, ephemeralPublicKey);
            console.log(`Node manual shared secret length: ${{manualSharedSecret.length}}, hex: ${{Buffer.from(manualSharedSecret).toString('hex').substring(0, 32)}}...`);
        }} catch (error) {{
            console.error(`Failed to calculate manual shared secret: ${{error}}`);
        }}
        
        try {{
            const decryptedBytes = await decrypt(encryptedPayload, keyEnvelope);
            const decryptedText = new TextDecoder().decode(decryptedBytes);
            console.log(`Decryption successful! Message: "${{decryptedText}}"`);
            process.exit(0);
        }} catch (error) {{
            console.error(`Decryption failed: ${{error}}`);
            process.exit(1);
        }}
    }}
    
    main();
    """
    
    stdout, stderr, exit_code = run_node_script(node_script)
    
    print(f"\n5. Node.js decryption result (exit code: {exit_code}):")
    if exit_code == 0:
        print(f"SUCCESS: {stdout}")
    else:
        print(f"FAILED: {stderr}")
    
    # Try the reverse direction
    print("\n=== TESTING REVERSE DIRECTION ===")
    
    # Create a Node.js script to generate a key pair and encrypt a message
    print("\n1. Generating key pair and encrypting in Node.js...")
    node_script = f"""
    import {{ generateKeyPair, encrypt }} from '{os.path.abspath(Path(__file__).parent)}/dist/index.mjs';
    
    async function main() {{
        try {{
            const keyEnvelope = await generateKeyPair();
            const message = new TextEncoder().encode('Hello from Node.js to Python!');
            const encryptedPayload = await encrypt(message, keyEnvelope.public_key);
            
            console.log(JSON.stringify({{
                keyEnvelope,
                encryptedPayload
            }}));
            process.exit(0);
        }} catch (error) {{
            console.error(`Encryption failed: ${{error}}`);
            process.exit(1);
        }}
    }}
    
    main();
    """
    
    stdout, stderr, exit_code = run_node_script(node_script)
    
    if exit_code != 0:
        print(f"Node.js encryption failed: {stderr}")
        return
    
    # Parse the Node.js output
    try:
        node_data = json.loads(stdout)
        node_key_envelope = node_data['keyEnvelope']
        node_encrypted_payload = node_data['encryptedPayload']
        
        print("\n2. Node.js encryption result:")
        print(f"Public key: {node_key_envelope['public_key'][:16]}...")
        print(f"Ephemeral public key: {node_encrypted_payload['ephemeral_public_key'][:16]}...")
        print(f"Nonce: {node_encrypted_payload['nonce'][:16]}...")
        print(f"Ciphertext: {node_encrypted_payload['ciphertext'][:16]}...")
        
        # Convert to Python objects
        py_key_envelope = KeyEnvelope(**node_key_envelope)
        py_encrypted_payload = EncryptedPayload(**node_encrypted_payload)
        
        # Attempt to decrypt in Python
        print("\n3. Attempting to decrypt in Python...")
        from src.py.crypto import decrypt
        
        # Print private key and ephemeral public key details
        import base64
        private_key_bytes = base64.urlsafe_b64decode(py_key_envelope.private_key + '=' * (4 - len(py_key_envelope.private_key) % 4))
        ephemeral_public_key_bytes = base64.urlsafe_b64decode(py_encrypted_payload.ephemeral_public_key + '=' * (4 - len(py_encrypted_payload.ephemeral_public_key) % 4))
        
        print(f"Python private key length: {len(private_key_bytes)}, hex: {private_key_bytes.hex()[:32]}...")
        print(f"Python ephemeral public key length: {len(ephemeral_public_key_bytes)}, hex: {ephemeral_public_key_bytes.hex()[:32]}...")
        
        # Try to manually calculate the shared secret
        import nacl.public
        try:
            x25519_private_key_obj = nacl.public.PrivateKey(private_key_bytes)
            ephemeral_public_key_obj = nacl.public.PublicKey(ephemeral_public_key_bytes)
            box = nacl.public.Box(x25519_private_key_obj, ephemeral_public_key_obj)
            x25519_shared_secret = box.shared_key()
            print(f"Python manual shared secret length: {len(x25519_shared_secret)}, hex: {x25519_shared_secret.hex()[:32]}...")
        except Exception as e:
            print(f"Failed to calculate manual shared secret: {e}")
        
        try:
            decrypted_message = decrypt(py_encrypted_payload, py_key_envelope)
            print(f"SUCCESS: Decrypted message: {decrypted_message.decode('utf-8')}")
        except Exception as e:
            print(f"FAILED: Python decryption error: {e}")
    except Exception as e:
        print(f"Error processing Node.js output: {e}")

if __name__ == "__main__":
    main()
