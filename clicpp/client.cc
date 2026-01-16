#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <memory>

// Include httplib (Download from https://github.com/yhirose/cpp-httplib)
#include "httplib.h"

// Include secp256k1 (Requires libsecp256k1 installation)
#include <secp256k1.h>
#include <secp256k1_recovery.h>

// Assuming you have a Keccak256 implementation, or use OpenSSL.
// Here is a Keccak256 wrapper example based on OpenSSL EVP for demonstration.
// Note: If your environment lacks Keccak256 support, replace this with the Hash function actually used by your project.
#include <openssl/evp.h>

namespace seth_client {

// ==========================================
// 1. Utils: Hex Encoding/Decoding & Hash
// ==========================================
class Utils {
public:
    static std::string ToHex(const std::string& input) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char c : input) {
            ss << std::setw(2) << (int)c;
        }
        return ss.str();
    }

    static std::string FromHex(const std::string& hex) {
        std::string bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    static std::string Uint64ToBytes(uint64_t val) {
        // Direct memory copy to maintain the same byte order as the server (usually Little Endian)
        std::string res;
        res.resize(sizeof(val));
        memcpy(&res[0], &val, sizeof(val));
        return res;
    }

    // Keccak256 Implementation (Requires linking -lssl -lcrypto)
    static std::string Keccak256(const std::string& data) {
        unsigned char hash[32];
        unsigned int hash_len;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        // Note: OpenSSL 3.0+ supports EVP_keccak256(). Older versions might need manual OID lookup or use sha3_256.
        const EVP_MD* md = EVP_keccak256(); 
        if (!md) {
            std::cerr << "EVP_keccak256 not found! Using SHA256 as fallback for demo." << std::endl;
            md = EVP_sha256(); // Demo only. Must use Keccak256 in production.
        }
        
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, data.c_str(), data.size());
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);
        return std::string((char*)hash, hash_len);
    }
};

// ==========================================
// 2. Core Logic: Replicate GetTxMessageHash
// ==========================================
struct TxParams {
    uint64_t nonce;
    std::string from_pubkey_hex; // Raw Public Key Hex
    std::string to_addr_hex;     // Target Address Hex
    uint64_t amount;
    uint64_t gas_limit;
    uint64_t gas_price;
    uint32_t type;               // Corresponds to 'step'
    
    // Optional parameters
    std::string contract_code_hex;
    std::string input_hex;
    uint64_t prepayment = 0;
    std::string key;
    std::string value;
};

class TxBuilder {
public:
    // Construct serialization data strictly following server's GetTxMessageHash logic
    static std::string ComputeHash(const TxParams& tx) {
        std::string message;
        // Reserve size to avoid frequent realloc
        message.reserve(512);

        // 1. nonce (uint64)
        message.append(Utils::Uint64ToBytes(tx.nonce));

        // 2. pubkey (bytes) - Server uses HexDecoded data
        message.append(Utils::FromHex(tx.from_pubkey_hex));

        // 3. to (bytes) - Server uses HexDecoded data
        message.append(Utils::FromHex(tx.to_addr_hex));

        // 4. amount (uint64)
        message.append(Utils::Uint64ToBytes(tx.amount));

        // 5. gas_limit (uint64)
        message.append(Utils::Uint64ToBytes(tx.gas_limit));

        // 6. gas_price (uint64)
        message.append(Utils::Uint64ToBytes(tx.gas_price));

        // 7. step (uint64) 
        // Server logic: if (tx_info.has_step()).
        // Since server's CreateTransactionWithAttr always calls new_tx->set_step(...),
        // Non-default or optional fields in Proto3 will be serialized. 
        // We assume 'type' is hashed if provided.
        // Note: Server stores 'step' as uint64 (message.append((char*)&step...)), even if input is uint32.
        uint64_t step_val = static_cast<uint64_t>(tx.type);
        message.append(Utils::Uint64ToBytes(step_val));

        // 8. contract_code (bytes)
        if (!tx.contract_code_hex.empty()) {
            message.append(Utils::FromHex(tx.contract_code_hex));
        }

        // 9. input (bytes)
        if (!tx.input_hex.empty()) {
            message.append(Utils::FromHex(tx.input_hex));
        }

        // 10. prepayment (uint64)
        if (tx.prepayment > 0) {
            message.append(Utils::Uint64ToBytes(tx.prepayment));
        }

        // 11. key & value (string)
        if (!tx.key.empty()) {
            message.append(tx.key); // Key is direct string, no hex decode needed
            if (!tx.value.empty()) {
                message.append(tx.value); // Same for Value
            }
        }

        return Utils::Keccak256(message);
    }
};

// ==========================================
// 3. Signing Logic
// ==========================================
struct Signature {
    std::string r;
    std::string s;
    int v;
};

class Signer {
public:
    static Signature Sign(const std::string& msg_hash, const std::string& private_key_hex) {
        Signature res;
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        
        std::string priv_bytes = Utils::FromHex(private_key_hex);
        secp256k1_ecdsa_recoverable_signature sig;
        
        // Sign
        secp256k1_ecdsa_sign_recoverable(
            ctx, 
            &sig, 
            (const unsigned char*)msg_hash.data(), 
            (const unsigned char*)priv_bytes.data(), 
            NULL, 
            NULL
        );

        unsigned char output64[64];
        int recid;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, &recid, &sig);

        res.r = Utils::ToHex(std::string((char*)output64, 32));
        res.s = Utils::ToHex(std::string((char*)output64 + 32, 32));
        res.v = recid; // v is 0 or 1. If chain requires EIP-155 (v + 27...), adjust here.

        secp256k1_context_destroy(ctx);
        return res;
    }
    
    // Derive Public Key from Private Key 
    // (Uncompressed 65 bytes -> Remove '04' prefix -> 64 bytes Hex)
    // Server CreateTransactionWithAttr sets pubkey directly after HexDecode.
    static std::string GetPublicKey(const std::string& private_key_hex) {
         secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
         std::string priv_bytes = Utils::FromHex(private_key_hex);
         secp256k1_pubkey pubkey;
         secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)priv_bytes.data());
         
         // Serialize to uncompressed format (65 bytes: 0x04 + X + Y)
         unsigned char pub[65];
         size_t len = 65;
         secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
         secp256k1_context_destroy(ctx);
         
         // Return Hex String
         return Utils::ToHex(std::string((char*)pub, 65));
    }
};

// ==========================================
// 4. Main Transaction Sender
// ==========================================
void SendTransaction(const std::string& host, int port, const TxParams& params, const std::string& private_key) {
    httplib::Client cli(host, port);
    cli.set_connection_timeout(5);

    // 1. Compute Hash Locally (Must match server's GetTxMessageHash)
    std::string tx_hash = TxBuilder::ComputeHash(params);
    std::cout << "[Client] Computed Hash: " << Utils::ToHex(tx_hash) << std::endl;

    // 2. Sign Locally
    Signature sig = Signer::Sign(tx_hash, private_key);
    std::cout << "[Client] Signature R: " << sig.r << std::endl;
    std::cout << "[Client] Signature S: " << sig.s << std::endl;
    std::cout << "[Client] Signature V: " << sig.v << std::endl;

    // 3. Construct HTTP Parameters
    httplib::Params http_params;
    http_params.emplace("nonce", std::to_string(params.nonce));
    http_params.emplace("pubkey", params.from_pubkey_hex); // Server does HexDecode
    http_params.emplace("to", params.to_addr_hex);         // Server does HexDecode
    http_params.emplace("amount", std::to_string(params.amount));
    http_params.emplace("gas_limit", std::to_string(params.gas_limit));
    http_params.emplace("gas_price", std::to_string(params.gas_price));
    http_params.emplace("type", std::to_string(params.type));
    http_params.emplace("shard_id", "0"); // Assume shard_id is 0, modify as needed

    // Signature Parameters
    http_params.emplace("sign_r", sig.r); // Server does HexDecode
    http_params.emplace("sign_s", sig.s); // Server does HexDecode
    http_params.emplace("sign_v", std::to_string(sig.v));

    // Optional Parameters
    if (!params.contract_code_hex.empty()) http_params.emplace("bytes_code", params.contract_code_hex);
    if (!params.input_hex.empty()) http_params.emplace("input", params.input_hex);
    if (params.prepayment > 0) http_params.emplace("pepay", std::to_string(params.prepayment));
    if (!params.key.empty()) http_params.emplace("key", params.key);
    if (!params.value.empty()) http_params.emplace("val", params.value);

    // 4. Send POST Request
    auto res = cli.Post("/transaction", http_params);

    if (res) {
        std::cout << "[Server Response] Status: " << res->status << ", Body: " << res->body << std::endl;
    } else {
        std::cerr << "[Error] Request failed!" << std::endl;
    }
}

} // namespace seth_client

// ==========================================
// Main
// ==========================================
int main() {
    // Simulated Private Key
    std::string private_key = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    
    // Generate Public Key from Private Key
    std::string pubkey = seth_client::Signer::GetPublicKey(private_key);

    // Prepare Transaction Parameters
    seth_client::TxParams tx;
    tx.nonce = 1;
    tx.from_pubkey_hex = pubkey;
    tx.to_addr_hex = "1234567890abcdef1234567890abcdef12345678"; // 20-byte hex
    tx.amount = 1000;
    tx.gas_limit = 50000;
    tx.gas_price = 1;
    tx.type = 0; // StepType

    // Example: With Input data
    tx.input_hex = "aabbcc"; 
    
    // Send
    seth_client::SendTransaction("localhost", 8888, tx, private_key);

    return 0;
}