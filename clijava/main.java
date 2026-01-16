import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SethClient {

    private final String baseUrl;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    public SethClient(String host, int port) {
        this.baseUrl = "http://" + host + ":" + port;
        this.httpClient = new OkHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    // Helper: Convert long (uint64) to 8-byte Little Endian array
    private byte[] longToBytesLE(long val) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(val);
        return buffer.array();
    }

    // Helper: Hex string to byte array
    private byte[] hexToBytes(String hex) {
        return Numeric.hexStringToByteArray(hex);
    }

    /**
     * Derive Address from Private Key
     * Logic: Last 20 bytes of Keccak256(RawPublicKey without '04' prefix)
     */
    public String deriveAddress(ECKeyPair keyPair) {
        // Web3j's getPublicKey() returns a BigInteger. 
        // We need the uncompressed public key bytes (64 bytes).
        byte[] pubKeyBytes = Numeric.toBytesPadded(keyPair.getPublicKey(), 64);
        
        // Compute Keccak256
        Keccak.Digest256 digest = new Keccak.Digest256();
        byte[] hash = digest.digest(pubKeyBytes);
        
        // Take last 20 bytes
        byte[] addressBytes = Arrays.copyOfRange(hash, hash.length - 20, hash.length);
        return Numeric.toHexStringNoPrefix(addressBytes);
    }

    /**
     * Query account info and get the latest Nonce
     */
    public long getLatestNonce(String addressHex) {
        System.out.println("[Client] Querying nonce for address: " + addressHex);
        
        RequestBody formBody = new FormBody.Builder()
                .add("address", addressHex)
                .build();

        Request request = new Request.Builder()
                .url(baseUrl + "/query_account")
                .post(formBody)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) return 0;
            String body = response.body().string();
            
            // Parse JSON
            JsonNode rootNode = objectMapper.readTree(body);
            if (rootNode.has("nonce")) {
                return rootNode.get("nonce").asLong(0);
            }
        } catch (Exception e) {
            System.err.println("[Warning] Failed to query nonce: " + e.getMessage());
        }
        return 0; // Default to 0 if new account or error
    }

    /**
     * Serialize data strictly following C++ GetTxMessageHash logic
     */
    public byte[] computeHash(long nonce, String pubKeyHex, String toHex, 
                              long amount, long gasLimit, long gasPrice, long step,
                              String contractCode, String inputHex, long prepayment,
                              String key, String val) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        // 1. nonce (uint64 LE)
        buffer.write(longToBytesLE(nonce));

        // 2. pubkey (bytes)
        buffer.write(hexToBytes(pubKeyHex));

        // 3. to (bytes)
        buffer.write(hexToBytes(toHex));

        // 4. amount (uint64 LE)
        buffer.write(longToBytesLE(amount));

        // 5. gas_limit (uint64 LE)
        buffer.write(longToBytesLE(gasLimit));

        // 6. gas_price (uint64 LE)
        buffer.write(longToBytesLE(gasPrice));

        // 7. step (uint64 LE) - Cast int to long for 8-byte serialization
        buffer.write(longToBytesLE(step));

        // 8. contract_code (bytes)
        if (contractCode != null && !contractCode.isEmpty()) {
            buffer.write(hexToBytes(contractCode));
        }

        // 9. input (bytes)
        if (inputHex != null && !inputHex.isEmpty()) {
            buffer.write(hexToBytes(inputHex));
        }

        // 10. prepayment (uint64 LE)
        if (prepayment > 0) {
            buffer.write(longToBytesLE(prepayment));
        }

        // 11. key & val (UTF-8 bytes)
        if (key != null && !key.isEmpty()) {
            buffer.write(key.getBytes(StandardCharsets.UTF_8));
            if (val != null && !val.isEmpty()) {
                buffer.write(val.getBytes(StandardCharsets.UTF_8));
            }
        }

        // Compute Keccak256
        Keccak.Digest256 digest = new Keccak.Digest256();
        return digest.digest(buffer.toByteArray());
    }

    /**
     * Internal method to sign and post
     */
    private boolean signAndSend(byte[] txHash, ECKeyPair keyPair, 
                                Map<String, String> params, int vOverride) {
        // Sign (ECDSA)
        // 'false' means we pass the hash directly, do not hash again
        Sign.SignatureData signature = Sign.signMessage(txHash, keyPair, false);

        String signR = Numeric.toHexStringNoPrefix(signature.getR());
        String signS = Numeric.toHexStringNoPrefix(signature.getS());
        
        // Native V (0/1) calculation
        // Web3j returns Ethereum standard V (27 or 28), we need to subtract 27
        int v = signature.getV()[0] - 27;

        // Apply override if needed
        if (vOverride != -1) {
            v = vOverride;
        }

        // Construct Form Data
        FormBody.Builder formBuilder = new FormBody.Builder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            formBuilder.add(entry.getKey(), entry.getValue());
        }
        formBuilder.add("sign_r", signR);
        formBuilder.add("sign_s", signS);
        formBuilder.add("sign_v", String.valueOf(v));

        Request request = new Request.Builder()
                .url(baseUrl + "/transaction")
                .post(formBuilder.build())
                .build();

        System.out.println("[Client] Sending Transaction with V=" + v + "...");
        
        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body().string();
            System.out.println("[Server Response] " + response.code() + ": " + body);
            
            return response.isSuccessful() && body.contains("ok");
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Automatic Workflow:
     * 1. Derive Address & PubKey
     * 2. Query Network for latest Nonce
     * 3. Nonce + 1
     * 4. Sign and Send (with Auto-Retry)
     */
    public void sendTransactionAuto(String privateKeyHex, String toHex, long amount, String inputHex) {
        try {
            // 1. Prepare Keys
            BigInteger privKey = Numeric.toBigInt(privateKeyHex);
            ECKeyPair keyPair = ECKeyPair.create(privKey);

            // Get Full Public Key (65 bytes with 04 prefix)
            // Web3j public key is BigInt, we pad it to 64 bytes and add 04
            String pubKeyHex = "04" + Numeric.toHexStringNoPrefixZeroPadded(keyPair.getPublicKey(), 128);
            
            // Derive Address
            String myAddressHex = deriveAddress(keyPair);
            
            // 2. Get and Increment Nonce
            long currentNonce = getLatestNonce(myAddressHex);
            long nextNonce = currentNonce + 1;
            System.out.println("[Client] Using Next Nonce: " + nextNonce);

            // Base Parameters
            long gasLimit = 50000;
            long gasPrice = 1;
            long step = 0;
            long shardId = 0;
            String contractCode = "";
            long prepayment = 0;
            String key = "";
            String val = "";

            // 3. Compute Hash
            byte[] txHash = computeHash(nextNonce, pubKeyHex, toHex, amount, gasLimit, gasPrice, step,
                    contractCode, inputHex, prepayment, key, val);

            System.out.println("[Client] Computed Hash: " + Numeric.toHexString(txHash));

            // Prepare Param Map
            Map<String, String> params = new HashMap<>();
            params.put("nonce", String.valueOf(nextNonce));
            params.put("pubkey", pubKeyHex);
            params.put("to", toHex);
            params.put("amount", String.valueOf(amount));
            params.put("gas_limit", String.valueOf(gasLimit));
            params.put("gas_price", String.valueOf(gasPrice));
            params.put("shard_id", String.valueOf(shardId));
            params.put("type", String.valueOf(step)); // API param is 'type'
            if (!inputHex.isEmpty()) params.put("input", inputHex);

            // 4. Sign and Send (First attempt, use calculated V)
            boolean success = signAndSend(txHash, keyPair, params, -1);

            // 5. Auto Retry Logic
            if (!success) {
                System.out.println("[Client] Transaction failed (likely V mismatch). Retrying with forced V=1...");
                signAndSend(txHash, keyPair, params, 1);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ==========================================
    // Main Entry Point
    // ==========================================
    public static void main(String[] args) {
        String host = "35.184.150.163";
        int port = 23001;
        
        String privateKey = "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848";
        String toAddress = "1234567890abcdef1234567890abcdef12345678";

        SethClient client = new SethClient(host, port);
        
        // Execute Auto Flow
        client.sendTransactionAuto(privateKey, toAddress, 5000, "112233");
    }
}