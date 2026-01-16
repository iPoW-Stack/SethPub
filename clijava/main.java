import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class SethClient {

    private final String baseUrl;
    private final HttpClient httpClient;

    public SethClient(String host, int port) {
        this.baseUrl = "http://" + host + ":" + port + "/transaction";
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Convert long (uint64) to 8-byte Little Endian array
     * Corresponds to C++: std::string((char*)&val, sizeof(val))
     */
    private byte[] longToBytesLE(long val) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(val);
        return buffer.array();
    }

    /**
     * Convert Hex string to byte[] (handles 0x prefix)
     */
    private byte[] hexToBytes(String hex) {
        return Numeric.hexStringToByteArray(hex);
    }

    /**
     * Strictly replicates the serialization logic of the server-side C++ GetTxMessageHash
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

        // 7. step (uint64 LE)
        // Key Point: Even if the input is uint32, the C++ server converts it to uint64 during serialization
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

    public void sendTransaction(String privateKeyHex, String toHex, long amount,
                                long nonce, long gasLimit, long gasPrice, 
                                int step, int shardId,
                                String contractCode, String inputHex, long prepayment,
                                String key, String val) {
        try {
            // 1. Handle Private Key
            BigInteger privKey = Numeric.toBigInt(privateKeyHex);
            ECKeyPair keyPair = ECKeyPair.create(privKey);

            // Derive Public Key (Web3j exports as BigInt by default, needs conversion to Hex)
            // Uncompressed Public Key format (64 bytes X+Y or 65 bytes 04+X+Y)
            // The C++ code seems to use the full Hex starting with 04, adding 04 here
            String pubKeyHex = "04" + keyPair.getPublicKey().toString(16);
            
            // If the server requires removing 04, use the line below:
            // String pubKeyHex = keyPair.getPublicKey().toString(16); 

            // 2. Compute Hash
            byte[] txHash = computeHash(nonce, pubKeyHex, toHex, amount, gasLimit, gasPrice, step,
                    contractCode, inputHex, prepayment, key, val);
            
            System.out.println("[Client] Computed Hash: " + Numeric.toHexString(txHash));

            // 3. Sign (ECDSA)
            // Sign.signMessage generates R, S, V
            Sign.SignatureData signature = Sign.signMessage(txHash, keyPair, false);

            String signR = Numeric.toHexStringNoPrefix(signature.getR());
            String signS = Numeric.toHexStringNoPrefix(signature.getS());
            
            // Web3j's V is usually 27 or 28 (Ethereum standard)
            // C++ native libsecp256k1 is usually 0 or 1
            // Conversion needed: V_native = V_eth - 27
            int v = signature.getV()[0] - 27;

            // 4. Construct HTTP Parameters
            Map<String, String> params = new HashMap<>();
            params.put("nonce", String.valueOf(nonce));
            params.put("pubkey", pubKeyHex); // No 0x prefix
            params.put("to", toHex);         // No 0x prefix
            params.put("amount", String.valueOf(amount));
            params.put("gas_limit", String.valueOf(gasLimit));
            params.put("gas_price", String.valueOf(gasPrice));
            params.put("shard_id", String.valueOf(shardId));
            params.put("type", String.valueOf(step));

            params.put("sign_r", signR);
            params.put("sign_s", signS);
            params.put("sign_v", String.valueOf(v));

            if (contractCode != null && !contractCode.isEmpty()) params.put("bytes_code", contractCode);
            if (inputHex != null && !inputHex.isEmpty()) params.put("input", inputHex);
            if (prepayment > 0) params.put("pepay", String.valueOf(prepayment));
            if (key != null && !key.isEmpty()) params.put("key", key);
            if (val != null && !val.isEmpty()) params.put("val", val);

            // 5. Send Request
            postForm(params);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void postForm(Map<String, String> params) throws IOException, InterruptedException {
        StringJoiner sj = new StringJoiner("&");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String value = entry.getValue() != null ? entry.getValue() : "";
            // URL encode values (not strictly necessary for Hex strings, but good for generality)
            sj.add(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "=" + 
                   URLEncoder.encode(value, StandardCharsets.UTF_8));
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(sj.toString()))
                .build();

        System.out.println("[Client] Sending request: " + sj.toString());
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println("[Server Response] Status: " + response.statusCode());
        System.out.println("[Server Response] Body: " + response.body());
    }

    // ==========================================
    // Main Entry Point
    // ==========================================
    public static void main(String[] args) {
        // Configuration
        String host = "127.0.0.1";
        int port = 8888;
        
        // Test Private Key and Address
        String privateKey = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String toAddress = "1234567890abcdef1234567890abcdef12345678"; // 40 chars hex

        SethClient client = new SethClient(host, port);
        
        // Send Transaction
        client.sendTransaction(
            privateKey,
            toAddress,
            1000,   // amount
            1,      // nonce
            50000,  // gasLimit
            1,      // gasPrice
            0,      // step
            0,      // shardId
            "",     // contractCode
            "aabbcc", // input
            0,      // prepayment
            "",     // key
            ""      // val
        );
    }
}