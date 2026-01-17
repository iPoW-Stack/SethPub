#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <memory>
#include <thread>
#include <chrono>

// Include dependencies
#include "httplib.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

using json = nlohmann::json;

namespace seth_client {

// ==========================================
// 1. Utils: Hex, Endian, Hash
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

    // Convert uint64 to 8-byte Little Endian string
    static std::string Uint64ToBytes(uint64_t val) {
        std::string res;
        res.resize(8);
        // Assuming running on x86/ARM Little Endian machine, direct copy works
        memcpy(&res[0], &val, 8);
        return res;
    }

    // Keccak256 Implementation (Depends on OpenSSL 3.0+)
    static std::string Keccak256(const std::string& data) {
        unsigned char hash[32];
        unsigned int hash_len;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        
        // Note: Must use keccak256, not sha3_256 (different padding)
        const EVP_MD* md = EVP_keccak256(); 
        if (!md) {
            std::cerr << "[Error] EVP_keccak256 not found! Ensure OpenSSL 3.0+ is installed." << std::endl;
            exit(1);
        }
        
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, data.c_str(), data.size());
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);
        return std::string((char*)hash, hash_len);
    }
};

// ==========================================
// 2. Core Logic
// ==========================================
struct TxParams {
    uint64_t nonce;
    std::string from_pubkey_hex;
    std::string to_addr_hex;
    uint64_t amount;
    uint64_t gas_limit;
    uint64_t gas_price;
    uint32_t type; // step
    // Optional
    std::string contract_code_hex;
    std::string input_hex;
    uint64_t prepayment = 0;
    std::string key;
    std::string value;
};

class SethClient {
public:
    SethClient(const std::string& host, int port) 
        : host_(host), port_(port) {
        cli_ = std::make_unique<httplib::Client>(host, port);
        cli_->set_connection_timeout(5);
        cli_->set_read_timeout(5);
    }

    // Derive Public Key from Private Key (Hex string, starts with 04)
    std::string GetPublicKey(const std::string& private_key_hex) {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        std::string priv_bytes = Utils::FromHex(private_key_hex);
        secp256k1_pubkey pubkey;
        
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)priv_bytes.data())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to create public key");
        }
        
        // Serialize to uncompressed format (65 bytes: 04 + X + Y)
        unsigned char pub[65];
        size_t len = 65;
        secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        secp256k1_context_destroy(ctx);
        
        return Utils::ToHex(std::string((char*)pub, 65));
    }

    // Derive Address from Public Key
    // Logic: Last 20 bytes of Keccak256(RawPubkey[1...64])
    std::string DeriveAddress(const std::string& pubkey_hex_full) {
        std::string pub_bytes = Utils::FromHex(pubkey_hex_full);
        // Remove 04 prefix
        if (pub_bytes.size() == 65 && pub_bytes[0] == 0x04) {
            pub_bytes = pub_bytes.substr(1);
        }
        
        std::string hash = Utils::Keccak256(pub_bytes);
        // Take last 20 bytes
        std::string addr_bytes = hash.substr(hash.size() - 20);
        return Utils::ToHex(addr_bytes);
    }

    // Query Network for Latest Nonce
    uint64_t GetLatestNonce(const std::string& address_hex) {
        std::cout << "[Client] Querying nonce for address: " << address_hex << std::endl;
        httplib::Params params;
        params.emplace("address", address_hex);
        
        auto res = cli_->Post("/query_account", params);
        if (res && res->status == 200) {
            try {
                // Response might be empty string or JSON
                if (res->body.empty()) return 0;

                // Attempt to parse JSON
                // Example: {"nonce": "5", "balance": ...} or {"nonce": 5}
                auto j = json::parse(res->body);
                
                if (j.contains("nonce")) {
                    // Handle case where nonce is string or number
                    if (j["nonce"].is_string()) {
                        return std::stoull(j["nonce"].get<std::string>());
                    } else if (j["nonce"].is_number()) {
                        return j["nonce"].get<uint64_t>();
                    }
                }
                return 0; // Nonce field not found, likely a new account
            } catch (const std::exception& e) {
                std::cerr << "[Warning] JSON parse failed (" << e.what() << "), assuming nonce 0. Body: " << res->body << std::endl;
                return 0;
            }
        } else {
            std::cerr << "[Error] Query nonce failed. Status: " << (res ? res->status : -1) << std::endl;
            return 0;
        }
    }

    // Construct Hash of data to be signed (Serialization Logic)
    std::string ComputeHash(const TxParams& tx) {
        std::string message;
        message.reserve(512);

        message.append(Utils::Uint64ToBytes(tx.nonce));
        message.append(Utils::FromHex(tx.from_pubkey_hex)); // Internal HexDecode
        message.append(Utils::FromHex(tx.to_addr_hex));     // Internal HexDecode
        message.append(Utils::Uint64ToBytes(tx.amount));
        message.append(Utils::Uint64ToBytes(tx.gas_limit));
        message.append(Utils::Uint64ToBytes(tx.gas_price));
        
        // Step must be cast to uint64 for serialization
        message.append(Utils::Uint64ToBytes(static_cast<uint64_t>(tx.type)));

        if (!tx.contract_code_hex.empty()) message.append(Utils::FromHex(tx.contract_code_hex));
        if (!tx.input_hex.empty()) message.append(Utils::FromHex(tx.input_hex));
        if (tx.prepayment > 0) message.append(Utils::Uint64ToBytes(tx.prepayment));
        if (!tx.key.empty()) {
            message.append(tx.key);
            if (!tx.value.empty()) message.append(tx.value);
        }

        return Utils::Keccak256(message);
    }

    // Auto Workflow: Derive -> Query -> Increment -> Sign -> Send
    void SendTransactionAuto(const std::string& private_key_hex, 
                             const std::string& to_hex, 
                             uint64_t amount, 
                             const std::string& input_hex = "") {
        // 1. Prepare Keys
        std::string pubkey_hex = GetPublicKey(private_key_hex);
        std::string my_addr_hex = DeriveAddress(pubkey_hex);
        
        // 2. Get and Increment Nonce
        uint64_t current_nonce = GetLatestNonce(my_addr_hex);
        uint64_t next_nonce = current_nonce + 1;
        std::cout << "[Client] Using Next Nonce: " << next_nonce << std::endl;

        // 3. Construct Params
        TxParams tx;
        tx.nonce = next_nonce;
        tx.from_pubkey_hex = pubkey_hex;
        tx.to_addr_hex = to_hex;
        tx.amount = amount;
        tx.gas_limit = 50000;
        tx.gas_price = 1;
        tx.type = 0;
        tx.input_hex = input_hex;

        // 4. Compute Hash
        std::string tx_hash = ComputeHash(tx);
        std::cout << "[Client] Hash: " << Utils::ToHex(tx_hash) << std::endl;

        // 5. Sign (Support automatic retry for V)
        // Default attempt V=0 (via recid)
        if (!SignAndSend(tx_hash, private_key_hex, tx)) {
            // Note: Since libsecp256k1 calculates a deterministic recid,
            // if the server rejects it, it's usually a hash mismatch, not the V value.
            // However, we print a message here.
            std::cout << "[Client] Transaction likely failed." << std::endl;
        }
    }

private:
    std::unique_ptr<httplib::Client> cli_;
    std::string host_;
    int port_;

    // Sign and Send HTTP Request
    bool SignAndSend(const std::string& msg_hash, const std::string& priv_key_hex, const TxParams& tx) {
        // --- Sign ---
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        std::string priv_bytes = Utils::FromHex(priv_key_hex);
        secp256k1_ecdsa_recoverable_signature sig;
        
        secp256k1_ecdsa_sign_recoverable(ctx, &sig, 
            (const unsigned char*)msg_hash.data(), 
            (const unsigned char*)priv_bytes.data(), 
            NULL, NULL);

        unsigned char output64[64];
        int recid;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, &recid, &sig);
        secp256k1_context_destroy(ctx);

        std::string r = Utils::ToHex(std::string((char*)output64, 32));
        std::string s = Utils::ToHex(std::string((char*)output64 + 32, 32));
        
        // --- Construct HTTP ---
        httplib::Params params;
        params.emplace("nonce", std::to_string(tx.nonce));
        params.emplace("pubkey", tx.from_pubkey_hex);
        params.emplace("to", tx.to_addr_hex);
        params.emplace("amount", std::to_string(tx.amount));
        params.emplace("gas_limit", std::to_string(tx.gas_limit));
        params.emplace("gas_price", std::to_string(tx.gas_price));
        params.emplace("type", std::to_string(tx.type));
        params.emplace("shard_id", "0");

        params.emplace("sign_r", r);
        params.emplace("sign_s", s);
        
        // Use the calculated recovery ID (0 or 1)
        params.emplace("sign_v", std::to_string(recid));

        if (!tx.input_hex.empty()) params.emplace("input", tx.input_hex);

        // --- Send ---
        std::cout << "[Client] Sending Request with V=" << recid << "..." << std::endl;
        auto res = cli_->Post("/transaction", params);

        if (res && res->status == 200) {
            std::cout << "[Server Response] " << res->body << std::endl;
            if (res->body.find("ok") != std::string::npos) return true;
            if (res->body.find("invalid") != std::string::npos) return false;
        } else {
            std::cerr << "[Error] HTTP failed: " << (res ? res->status : -1) << std::endl;
        }
        return true; 
    }
};

} // namespace seth_client

// ==========================================
// Main
// ==========================================
int main() {
    // Config
    std::string host = "35.184.150.163";
    int port = 23001;

    // Account
    std::string priv_key = "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848";
    std::string to_addr = "1234567890abcdef1234567890abcdef12345678";

    try {
        seth_client::SethClient client(host, port);
        
        // Run Auto Flow
        client.SendTransactionAuto(priv_key, to_addr, 5000, "112233");

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}