
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
    