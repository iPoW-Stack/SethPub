// npm install axios keccak secp256k1
const axios = require('axios');
const createKeccakHash = require('keccak');
const secp256k1 = require('secp256k1');
const { Buffer } = require('buffer');

// Helper function: Convert BigInt/Number to 8-byte Little Endian Buffer
// Corresponds to C++: std::string((char*)&val, sizeof(uint64))
function uint64ToBuffer(val) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(BigInt(val), 0);
    return buf;
}

// Helper function: Convert Hex to Buffer
function hexToBuffer(hex) {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    return Buffer.from(hex, 'hex');
}

class SethClient {
    constructor(host, port) {
        this.url = `http://${host}:${port}/transaction`;
    }

    /**
     * Strictly replicates the serialization logic of the server-side C++ GetTxMessageHash
     */
    computeHash(params) {
        const buffers = [];

        // 1. nonce (uint64)
        buffers.push(uint64ToBuffer(params.nonce));

        // 2. pubkey (bytes) - C++ receives raw bytes after HexDecode
        buffers.push(hexToBuffer(params.pubkey));

        // 3. to (bytes)
        buffers.push(hexToBuffer(params.to));

        // 4. amount (uint64)
        buffers.push(uint64ToBuffer(params.amount));

        // 5. gas_limit (uint64)
        buffers.push(uint64ToBuffer(params.gas_limit));

        // 6. gas_price (uint64)
        buffers.push(uint64ToBuffer(params.gas_price));

        // 7. step (uint64)
        // Key Point: Although input is uint32, server forces cast to uint64 during serialization
        buffers.push(uint64ToBuffer(params.step));

        // 8. contract_code (bytes)
        if (params.contract_code) {
            buffers.push(hexToBuffer(params.contract_code));
        }

        // 9. input (bytes)
        if (params.input) {
            buffers.push(hexToBuffer(params.input));
        }

        // 10. prepayment (uint64)
        if (params.prepayment > 0) {
            buffers.push(uint64ToBuffer(params.prepayment));
        }

        // 11. key & val (string bytes)
        // Corresponds to protobuf string, directly utf-8 encoded
        if (params.key) {
            buffers.push(Buffer.from(params.key, 'utf8'));
            if (params.val) {
                buffers.push(Buffer.from(params.val, 'utf8'));
            }
        }

        // Concatenate all Buffers
        const serialized = Buffer.concat(buffers);

        // Compute Keccak256
        return createKeccakHash('keccak256').update(serialized).digest();
    }

    async sendTransaction(privateKeyHex, txParams) {
        // 1. Handle Private Key
        if (privateKeyHex.startsWith('0x')) privateKeyHex = privateKeyHex.slice(2);
        const privateKey = Buffer.from(privateKeyHex, 'hex');

        // 2. Derive Public Key (Uncompressed format: 65 bytes, starts with 04)
        const pubKeyBytes = secp256k1.publicKeyCreate(privateKey, false);
        const pubKeyHex = Buffer.from(pubKeyBytes).toString('hex');

        // Note: If the server expects a 64-byte public key (removing '04' prefix), uncomment the line below
        // const pubKeyHex = Buffer.from(pubKeyBytes).toString('hex').slice(2);

        // Fill in parameters
        const params = {
            nonce: 1,
            amount: 0,
            gas_limit: 50000,
            gas_price: 1,
            step: 0,
            shard_id: 0,
            contract_code: '',
            input: '',
            prepayment: 0,
            key: '',
            val: '',
            ...txParams, // User input overrides defaults
            pubkey: pubKeyHex // Overrides computed public key
        };

        // 3. Compute Hash Locally
        const txHash = this.computeHash(params);
        console.log(`[Client] Computed Hash: ${txHash.toString('hex')}`);

        // 4. Sign (ECDSA Recoverable)
        const sigObj = secp256k1.ecdsaSign(txHash, privateKey);
        
        // sigObj.signature is 64 bytes (R 32 + S 32)
        // sigObj.recid is recovery id (0 or 1)
        const r = Buffer.from(sigObj.signature.slice(0, 32)).toString('hex');
        const s = Buffer.from(sigObj.signature.slice(32, 64)).toString('hex');
        const v = sigObj.recid;

        // 5. Construct HTTP Form Data
        // axios automatically converts object to application/json,
        // but the server typically expects application/x-www-form-urlencoded, so use URLSearchParams
        const formData = new URLSearchParams();
        formData.append('nonce', params.nonce);
        formData.append('pubkey', params.pubkey);
        formData.append('to', params.to);
        formData.append('amount', params.amount);
        formData.append('gas_limit', params.gas_limit);
        formData.append('gas_price', params.gas_price);
        formData.append('shard_id', params.shard_id);
        formData.append('type', params.step); // API parameter name is 'type'

        // Signature Data
        formData.append('sign_r', r);
        formData.append('sign_s', s);
        formData.append('sign_v', v);

        // Optional Parameters
        if (params.contract_code) formData.append('bytes_code', params.contract_code);
        if (params.input) formData.append('input', params.input);
        if (params.prepayment > 0) formData.append('pepay', params.prepayment);
        if (params.key) formData.append('key', params.key);
        if (params.val) formData.append('val', params.val);

        try {
            console.log(`[Client] Sending transaction to ${this.url}...`);
            const res = await axios.post(this.url, formData, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            console.log(`[Server Response] Status: ${res.status}, Body: ${res.data}`);
        } catch (error) {
            if (error.response) {
                console.error(`[Error] Server responded with ${error.response.status}: ${error.response.data}`);
            } else {
                console.error(`[Error] Request failed: ${error.message}`);
            }
        }
    }
}

// ==========================================
// Usage Example
// ==========================================
(async () => {
    const client = new SethClient('127.0.0.1', 8888);

    // Test Private Key (Example)
    const privateKey = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    
    // Target Address (40 chars hex)
    const toAddress = '1234567890abcdef1234567890abcdef12345678';

    await client.sendTransaction(privateKey, {
        to: toAddress,
        amount: 1000,
        nonce: 1,
        gas_limit: 50000,
        gas_price: 1,
        input: 'aabbcc' // Optional contract input
    });
})();