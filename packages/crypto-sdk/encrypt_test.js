
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
    