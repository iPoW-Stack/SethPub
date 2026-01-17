import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Hash
import org.web3j.crypto.Keys
import org.web3j.crypto.Sign
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

class SethClient(host: String, port: Int) {

    private val baseUrl = "http://$host:$port"
    private val httpClient = OkHttpClient()
    private val mapper = jacksonObjectMapper()

    /**
     * Helper: Convert Long (uint64) to 8-byte Little Endian ByteArray
     * Matches C++: std::string((char*)&val, sizeof(uint64))
     */
    private fun Long.toLittleEndianBytes(): ByteArray {
        return ByteBuffer.allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(this)
            .array()
    }

    private fun String.hexToBytes(): ByteArray = Numeric.hexStringToByteArray(this)
    private fun ByteArray.toHex(): String = Numeric.toHexStringNoPrefix(this)

    /**
     * Query account info and get the latest Nonce
     */
    fun getLatestNonce(addressHex: String): Long {
        println("[Client] Querying nonce for address: $addressHex")

        val formBody = FormBody.Builder()
            .add("address", addressHex)
            .build()

        val request = Request.Builder()
            .url("$baseUrl/query_account")
            .post(formBody)
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return 0L
                val body = response.body?.string() ?: return 0L
                
                // Parse JSON
                val rootNode = mapper.readTree(body)
                if (rootNode.has("nonce")) {
                    return rootNode["nonce"].asLong(0L)
                }
            }
        } catch (e: Exception) {
            System.err.println("[Warning] Failed to query nonce: ${e.message}")
        }
        return 0L // Default to 0
    }

    /**
     * Serialize data strictly following C++ GetTxMessageHash logic
     */
    fun computeHash(
        nonce: Long, pubKeyHex: String, toHex: String,
        amount: Long, gasLimit: Long, gasPrice: Long, step: Int,
        contractCode: String?, inputHex: String?, prepayment: Long,
        key: String?, valStr: String?
    ): ByteArray {

        // Estimate buffer size
        val buffer = ByteBuffer.allocate(4096).order(ByteOrder.LITTLE_ENDIAN)

        // 1. nonce (uint64 LE)
        buffer.putLong(nonce)

        // 2. pubkey (bytes)
        buffer.put(pubKeyHex.hexToBytes())

        // 3. to (bytes)
        buffer.put(toHex.hexToBytes())

        // 4. amount (uint64 LE)
        buffer.putLong(amount)

        // 5. gas_limit (uint64 LE)
        buffer.putLong(gasLimit)

        // 6. gas_price (uint64 LE)
        buffer.putLong(gasPrice)

        // 7. step (uint64 LE)
        // Key Point: Input is Int (uint32), but serialized as Long (uint64)
        buffer.putLong(step.toLong())

        // 8. contract_code (bytes)
        if (!contractCode.isNullOrEmpty()) buffer.put(contractCode.hexToBytes())

        // 9. input (bytes)
        if (!inputHex.isNullOrEmpty()) buffer.put(inputHex.hexToBytes())

        // 10. prepayment (uint64 LE)
        if (prepayment > 0L) buffer.putLong(prepayment)

        // 11. key & val (UTF-8 bytes)
        if (!key.isNullOrEmpty()) {
            buffer.put(key.toByteArray(StandardCharsets.UTF_8))
            if (!valStr.isNullOrEmpty()) {
                buffer.put(valStr.toByteArray(StandardCharsets.UTF_8))
            }
        }

        // Get actual bytes used
        val data = ByteArray(buffer.position())
        buffer.rewind()
        buffer.get(data)

        // Compute Keccak256
        return Hash.sha3(data)
    }

    /**
     * Internal method to sign and post
     */
    private fun signAndSend(
        txHash: ByteArray,
        keyPair: ECKeyPair,
        params: MutableMap<String, String>,
        vOverride: Int
    ): Boolean {
        // Sign (ECDSA)
        // 'false' = no hashing inside signMessage (since we already passed a hash)
        val signatureData = Sign.signMessage(txHash, keyPair, false)

        val r = signatureData.r.toHex()
        val s = signatureData.s.toHex()
        
        // Native V (0/1) calculation
        // Web3j returns Ethereum standard V (27 or 28), subtract 27
        var v = (signatureData.v[0] - 27).toInt()

        // Apply override
        if (vOverride != -1) {
            v = vOverride
        }

        // Construct Form Data
        val formBuilder = FormBody.Builder()
        params.forEach { (k, value) -> formBuilder.add(k, value) }
        
        formBuilder.add("sign_r", r)
        formBuilder.add("sign_s", s)
        formBuilder.add("sign_v", v.toString())

        val request = Request.Builder()
            .url("$baseUrl/transaction")
            .post(formBuilder.build())
            .build()

        println("[Client] Sending Transaction with V=$v...")

        try {
            httpClient.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                println("[Server Response] ${response.code}: $body")
                
                return response.isSuccessful && body.contains("ok")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }

    /**
     * Automatic Workflow
     */
    fun sendTransactionAuto(
        privateKeyHex: String,
        toHex: String,
        amount: Long,
        inputHex: String? = null
    ) {
        try {
            // 1. Prepare Keys
            val privKey = Numeric.toBigInt(privateKeyHex)
            val keyPair = ECKeyPair.create(privKey)

            // Get Full Public Key (65 bytes: 04 + X + Y)
            // Web3j public key is BigInt, pad to 64 bytes (128 hex chars) and prepend 04
            val pubKeyHex = "04" + Numeric.toHexStringNoPrefixZeroPadded(keyPair.publicKey, 128)

            // Derive Address (Standard Ethereum Logic: Keccak(Pub)[-20:])
            // Web3j provides a utility for this
            val myAddressHex = Keys.getAddress(keyPair)
            
            // 2. Get and Increment Nonce
            val currentNonce = getLatestNonce(myAddressHex)
            val nextNonce = currentNonce + 1
            println("[Client] Using Next Nonce: $nextNonce")

            // Base Parameters
            val gasLimit = 50000L
            val gasPrice = 1L
            val step = 0
            val shardId = 0
            val contractCode = ""
            val prepayment = 0L
            val key = ""
            val valStr = ""

            // 3. Compute Hash
            val txHash = computeHash(
                nextNonce, pubKeyHex, toHex, amount, gasLimit, gasPrice, step,
                contractCode, inputHex, prepayment, key, valStr
            )

            println("[Client] Computed Hash: ${txHash.toHex()}")

            // Prepare Param Map
            val params = mutableMapOf<String, String>()
            params["nonce"] = nextNonce.toString()
            params["pubkey"] = pubKeyHex
            params["to"] = toHex
            params["amount"] = amount.toString()
            params["gas_limit"] = gasLimit.toString()
            params["gas_price"] = gasPrice.toString()
            params["shard_id"] = shardId.toString()
            params["type"] = step.toString() // API param is 'type'
            if (!inputHex.isNullOrEmpty()) params["input"] = inputHex

            // 4. Sign and Send (First attempt, use calculated V)
            val success = signAndSend(txHash, keyPair, params, -1)

            // 5. Auto Retry Logic
            if (!success) {
                println("[Client] Transaction failed (likely V mismatch). Retrying with forced V=1...")
                signAndSend(txHash, keyPair, params, 1)
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}

// ==========================================
// Main Entry Point
// ==========================================
fun main() {
    val host = "35.184.150.163"
    val port = 23001
    
    val privateKey = "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848"
    val toAddress = "1234567890abcdef1234567890abcdef12345678" // 40 chars hex

    val client = SethClient(host, port)
    
    // Execute Auto Flow
    client.sendTransactionAuto(
        privateKeyHex = privateKey,
        toHex = toAddress,
        amount = 5000,
        inputHex = "112233"
    )
}