const axios = require('axios');
const createKeccakHash = require('keccak');
const secp256k1 = require('secp256k1');
const { Buffer } = require('buffer');

// Helper: Convert BigInt/Number to 8-byte Little Endian Buffer
// Corresponds to Python: struct.pack('<Q', val)
function uint64ToBuffer(val) {
    const buf = Buffer.alloc(8);
    // Ensure input is BigInt to handle large numbers safely
    buf.writeBigUInt64LE(BigInt(val), 0);
    return buf;
}

// Helper: Convert Hex string to Buffer
function hexToBuffer(hex) {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    return Buffer.from(hex, 'hex');
}

class SethClient {
    constructor(host, port) {
        this.baseUrl = `http://${host}:${port}`;
        this.txUrl = `${this.baseUrl}/transaction`;
        this.queryUrl = `${this.baseUrl}/query_account`;
    }

    /**
     * Derive Address from Public Key
     * Logic: Last 20 bytes of Keccak256(RawPublicKey without '04' prefix)
     */
    deriveAddressFromPubkey(pubKeyBytes) {
        // pubKeyBytes passed here should be the full uncompressed key (65 bytes)
        // We need to remove the first byte ('04') prefix
        const rawPubKey = pubKeyBytes.slice(1); 
        
        const hash = createKeccakHash('keccak256').update(rawPubKey).digest();
        // Take the last 20 bytes
        return hash.slice(-20).toString('hex');
    }

    /**
     * Query account info and get the latest Nonce
     */
    async getLatestNonce(addressHex) {
        console.log(`[Client] Querying nonce for address: ${addressHex}`);
        try {
            // Server expects x-www-form-urlencoded usually, using URLSearchParams
            const params = new URLSearchParams();
            params.append('address', addressHex);

            const res = await axios.post(this.queryUrl, params, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            if (res.status !== 200) {
                console.error(`[Error] Query failed: ${res.data}`);
                return 0;
            }

            // Response is typically JSON: {"nonce": 5, "balance": ...}
            // If it's a new account, fields might be missing.
            const data = res.data;
            // Handle parsing if axios didn't auto-parse JSON (depends on server content-type)
            const accountInfo = (typeof data === 'string') ? JSON.parse(data) : data;

            const nonce = parseInt(accountInfo.nonce || 0, 10);
            console.log(`[Client] Current Nonce on chain: ${nonce}`);
            return nonce;

        } catch (error) {
            console.error(`[Error] Get nonce error: ${error.message}`);
            return 0; // Assume 0 if query fails or account doesn't exist
        }
    }

    /**
     * Strictly replicates the serialization logic of C++ GetTxMessageHash
     */
    computeHash(params) {
        const buffers = [];

        // 1. nonce (uint64 LE)
        buffers.push(uint64ToBuffer(params.nonce));

        // 2. pubkey (bytes)
        buffers.push(hexToBuffer(params.pubkey));

        // 3. to (bytes)
        buffers.push(hexToBuffer(params.to));

        // 4. amount (uint64 LE)
        buffers.push(uint64ToBuffer(params.amount));

        // 5. gas_limit (uint64 LE)
        buffers.push(uint64ToBuffer(params.gas_limit));

        // 6. gas_price (uint64 LE)
        buffers.push(uint64ToBuffer(params.gas_price));

        // 7. step (uint64 LE) - Input is uint32, but serialized as uint64
        buffers.push(uint64ToBuffer(params.step));

        // 8. contract_code (bytes)
        if (params.contract_code) buffers.push(hexToBuffer(params.contract_code));

        // 9. input (bytes)
        if (params.input) buffers.push(hexToBuffer(params.input));

        // 10. prepayment (uint64 LE)
        if (params.prepayment > 0) buffers.push(uint64ToBuffer(params.prepayment));

        // 11. key & val (UTF-8 bytes)
        if (params.key) {
            buffers.push(Buffer.from(params.key, 'utf8'));
            if (params.val) buffers.push(Buffer.from(params.val, 'utf8'));
        }

        const serialized = Buffer.concat(buffers);
        return createKeccakHash('keccak256').update(serialized).digest();
    }

    /**
     * Automatic Workflow:
     * 1. Derive Public Key & Address
     * 2. Query Network for latest Nonce
     * 3. Nonce + 1
     * 4. Sign and Send
     */
    async sendTransactionAuto(privateKeyHex, txParams) {
        // --- 1. Prepare Keys ---
        if (privateKeyHex.startsWith('0x')) privateKeyHex = privateKeyHex.slice(2);
        const privateKey = Buffer.from(privateKeyHex, 'hex');

        // Generate Public Key (Uncompressed: 65 bytes, starts with 04)
        const pubKeyBytes = secp256k1.publicKeyCreate(privateKey, false);
        const pubKeyHex = Buffer.from(pubKeyBytes).toString('hex');

        // Derive Address
        const myAddressHex = this.deriveAddressFromPubkey(pubKeyBytes);
        
        // --- 2. Get and Increment Nonce ---
        const currentNonce = await this.getLatestNonce(myAddressHex);
        const nextNonce = currentNonce + 1;
        console.log(`[Client] Using Next Nonce: ${nextNonce}`);

        // Merge params
        const finalParams = {
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
            ...txParams,
            nonce: nextNonce,
            pubkey: pubKeyHex
        };

        // --- 3. Compute Hash ---
        const txHash = this.computeHash(finalParams);
        console.log(`[Client] Computed Hash: ${txHash.toString('hex')}`);

        // --- 4. Sign ---
        // secp256k1.ecdsaSign returns { signature: Uint8Array(64), recid: int }
        const sigObj = secp256k1.ecdsaSign(txHash, privateKey);
        
        const r = Buffer.from(sigObj.signature.slice(0, 32)).toString('hex');
        const s = Buffer.from(sigObj.signature.slice(32, 64)).toString('hex');
        // Initial V attempt (Native V is 0 or 1)
        let v = sigObj.recid;

        // --- 5. Send Request ---
        const sendReq = async (vValue) => {
            const formData = new URLSearchParams();
            formData.append('nonce', finalParams.nonce);
            formData.append('pubkey', finalParams.pubkey);
            formData.append('to', finalParams.to);
            formData.append('amount', finalParams.amount);
            formData.append('gas_limit', finalParams.gas_limit);
            formData.append('gas_price', finalParams.gas_price);
            formData.append('shard_id', finalParams.shard_id);
            formData.append('type', finalParams.step);
            
            formData.append('sign_r', r);
            formData.append('sign_s', s);
            formData.append('sign_v', vValue);

            // Optional
            if (finalParams.contract_code) formData.append('bytes_code', finalParams.contract_code);
            if (finalParams.input) formData.append('input', finalParams.input);
            if (finalParams.prepayment > 0) formData.append('pepay', finalParams.prepayment);
            if (finalParams.key) formData.append('key', finalParams.key);
            if (finalParams.val) formData.append('val', finalParams.val);

            console.log(`[Client] Sending Transaction with V=${vValue}...`);
            const res = await axios.post(this.txUrl, formData, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            return res;
        };

        try {
            // First attempt
            const res = await sendReq(v);
            console.log(`[Server Response] ${res.status}: ${JSON.stringify(res.data)}`);
            
            const respText = JSON.stringify(res.data);
            // Automatic Retry with V=1 if rejected
            if (respText.includes('SignatureInvalid') || respText.includes('verify signature failed')) {
                 if (v === 0) {
                     console.log("[Client] Signature rejected (V=0), retrying with V=1...");
                     const retryRes = await sendReq(1);
                     console.log(`[Server Response (Retry)] ${retryRes.status}: ${JSON.stringify(retryRes.data)}`);
                 }
            }
        } catch (error) {
            console.error(`[Error] Network error: ${error.message}`);
        }
    }
}

// ==========================================
// Run Test
// ==========================================
(async () => {
    const HOST = "35.184.150.163";
    const PORT = 23001;

    // Sender Private Key
    const MY_PRIVATE_KEY = "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848";
    
    // Receiver Address
    const TO_ADDR = "1234567890abcdef1234567890abcdef12345678"; 

    const client = new SethClient(HOST, PORT);

    // Call Automatic Workflow
    await client.sendTransactionAuto(MY_PRIVATE_KEY, {
        to: TO_ADDR,
        amount: 5000,
        input: "112233" // Optional: contract input
    });
})();