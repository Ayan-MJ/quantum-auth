# Quantum Auth Crypto SDK

A cross-language, post-quantum-ready cryptography SDK that provides hybrid X25519-Kyber768 encryption, resistant to attacks from both classical and quantum computers.

## Features

- **Hybrid Encryption**: Combines X25519 (classical security) with Kyber768 (quantum resistance)
- **Cross-Language Support**: Identical API and serialization in both TypeScript and Python
- **Password-Protected Keys**: Optional password-based encryption for private keys
- **Browser Compatible**: Works in both Node.js and browser environments
- **Thoroughly Tested**: Comprehensive test suite with cross-language compatibility tests

## Installation

### TypeScript/JavaScript

```bash
# Using npm
npm install @quantum-auth/crypto-sdk

# Using yarn
yarn add @quantum-auth/crypto-sdk

# Using pnpm
pnpm add @quantum-auth/crypto-sdk
```

### Python

```bash
# Using pip
pip install quantum-auth-crypto-sdk

# Using poetry
poetry add quantum-auth-crypto-sdk
```

## Usage

### TypeScript/JavaScript (Node.js)

```typescript
import { generateKeyPair, encrypt, decrypt } from "@quantum-auth/crypto-sdk";

async function example() {
  // Generate a key pair
  const keyEnvelope = await generateKeyPair();

  // Or with a password
  const passwordProtectedKeyEnvelope =
    await generateKeyPair("my-secure-password");

  // Encrypt a message
  const message = new TextEncoder().encode("Hello, quantum world!");
  const encryptedPayload = await encrypt(message, keyEnvelope.public_key);

  // Decrypt a message
  const decryptedMessage = await decrypt(encryptedPayload, keyEnvelope);
  console.log(new TextDecoder().decode(decryptedMessage)); // 'Hello, quantum world!'

  // Decrypt a password-protected message
  const decryptedPasswordMessage = await decrypt(
    encryptedPayload,
    passwordProtectedKeyEnvelope,
    "my-secure-password",
  );
}

example();
```

### TypeScript/JavaScript (Browser)

```typescript
import { generateKeyPair, encrypt, decrypt } from "@quantum-auth/crypto-sdk";

async function example() {
  // The SDK automatically initializes when you call any function
  const keyEnvelope = await generateKeyPair();

  // Store the key envelope securely
  localStorage.setItem("keyEnvelope", JSON.stringify(keyEnvelope));

  // Share only the public key with others
  const publicKey = keyEnvelope.public_key;

  // Later, retrieve the key envelope
  const retrievedKeyEnvelope = JSON.parse(localStorage.getItem("keyEnvelope"));

  // Encrypt data to send
  const message = new TextEncoder().encode("Secret message");
  const encryptedPayload = await encrypt(message, publicKey);

  // Send the encryptedPayload to the recipient

  // Decrypt received data
  const decryptedMessage = await decrypt(
    encryptedPayload,
    retrievedKeyEnvelope,
  );
  console.log(new TextDecoder().decode(decryptedMessage));
}

example();
```

### Python

```python
from quantum_auth_crypto_sdk import generate_key_pair, encrypt, decrypt

# Generate a key pair
key_envelope = generate_key_pair()

# Or with a password
password_protected_key_envelope = generate_key_pair("my-secure-password")

# Encrypt a message
message = b"Hello, quantum world!"
encrypted_payload = encrypt(message, key_envelope.public_key)

# Decrypt a message
decrypted_message = decrypt(encrypted_payload, key_envelope)
print(decrypted_message.decode('utf-8'))  # 'Hello, quantum world!'

# Decrypt a password-protected message
decrypted_password_message = decrypt(
    encrypted_payload,
    password_protected_key_envelope,
    "my-secure-password"
)
```

## API Reference

### TypeScript/JavaScript

#### `async generateKeyPair(passwordOrCredential?: string): Promise<KeyEnvelope>`

Generates a hybrid X25519-Kyber768 key pair.

- **Parameters**:
  - `passwordOrCredential` (optional): Password to encrypt the private key
- **Returns**: A `KeyEnvelope` containing the public key and encrypted private key

#### `async encrypt(plaintext: Uint8Array, recipientPubKey: string): Promise<EncryptedPayload>`

Encrypts data using a recipient's public key.

- **Parameters**:
  - `plaintext`: The data to encrypt as a `Uint8Array`
  - `recipientPubKey`: Base64url-encoded recipient public key
- **Returns**: An `EncryptedPayload` containing all necessary data for decryption

#### `async decrypt(payload: EncryptedPayload, envelope: KeyEnvelope, passwordOrCredential?: string): Promise<Uint8Array>`

Decrypts data using the recipient's private key.

- **Parameters**:
  - `payload`: The encrypted payload
  - `envelope`: The key envelope containing the encrypted private key
  - `passwordOrCredential` (optional): Password to decrypt the private key
- **Returns**: The decrypted data as a `Uint8Array`

### Python

#### `generate_key_pair(password_or_credential: Optional[str] = None) -> KeyEnvelope`

Generates a hybrid X25519-Kyber768 key pair.

- **Parameters**:
  - `password_or_credential` (optional): Password to encrypt the private key
- **Returns**: A `KeyEnvelope` containing the public key and encrypted private key

#### `encrypt(plaintext: bytes, recipient_pub_key: str) -> EncryptedPayload`

Encrypts data using a recipient's public key.

- **Parameters**:
  - `plaintext`: The data to encrypt as `bytes`
  - `recipient_pub_key`: Base64url-encoded recipient public key
- **Returns**: An `EncryptedPayload` containing all necessary data for decryption

#### `decrypt(payload: EncryptedPayload, envelope: KeyEnvelope, password_or_credential: Optional[str] = None) -> bytes`

Decrypts data using the recipient's private key.

- **Parameters**:
  - `payload`: The encrypted payload
  - `envelope`: The key envelope containing the encrypted private key
  - `password_or_credential` (optional): Password to decrypt the private key
- **Returns**: The decrypted data as `bytes`

## Security Considerations

- **Key Storage**: Always store private keys securely, preferably encrypted with a strong password
- **Password Strength**: Use strong, unique passwords for key protection
- **Browser Limitations**: In browsers without WebAssembly support, the SDK falls back to X25519-only encryption
- **Quantum Resistance**: The hybrid approach provides protection against both classical and quantum attacks

## Development

### Building the SDK

```bash
# Install dependencies
pnpm install

# Build the TypeScript package
pnpm build

# Run tests
pnpm test
```

### Running Python Tests

```bash
# Install dependencies
poetry install

# Run tests
pytest

# Run with coverage
pytest --cov=src/py
```

## License

MIT
