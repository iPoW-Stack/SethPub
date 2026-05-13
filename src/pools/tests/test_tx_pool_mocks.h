// Shared test mocks for pools_test (security, optional AccountManager hook).
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "common/utils.h"
#include "protos/address.pb.h"
#include "security/security.h"

namespace seth {
namespace pools {
namespace test {

// When non-empty, block::AccountManager::GetAccountInfo (stub in test_pools_stubs.cc)
// delegates here so tests can return synthetic AddressInfo without linking full block.
extern std::function<std::shared_ptr<address::protobuf::AddressInfo>(const std::string&)>
    g_test_account_info_override;

// With SETH_UNITTEST on pools (coverage), TxPoolManager::SetIsOtherLeaderHookForTest mocks
// HotstuffManager::is_other_leader without linking consensus (see tx_pool_manager.h).

inline std::shared_ptr<address::protobuf::AddressInfo> MakeTestAddressInfo(
        uint32_t pool_index,
        const std::string& addr,
        uint32_t sharding_id = common::kInvalidUint32) {
    auto p = std::make_shared<address::protobuf::AddressInfo>();
    p->set_pool_index(pool_index);
    p->set_addr(addr);
    p->set_sharding_id(sharding_id);
    return p;
}

// Minimal security::Security for TxPoolManager / firewall paths.
// GetAddress(const std::string&) returns addr_ (covers GetAddressWithPublicKey if it forwards).
class FakeSecurityForTxPm final : public security::Security {
public:
    explicit FakeSecurityForTxPm(std::string addr) : addr_(std::move(addr)), pubkey_("pk") {}

    void set_verify_always_success(bool v) { verify_ok_ = v; }

    int SetPrivateKey(const std::string&) override { return security::kSecuritySuccess; }
    int SetPrivateKey(const char*, uint32_t) override { return security::kSecuritySuccess; }
    int Sign(const std::string&, std::string*) override { return security::kSecurityError; }
    int Verify(const std::string&, const std::string&, const std::string&) override {
        return verify_ok_ ? security::kSecuritySuccess : security::kSecurityError;
    }
    std::string Recover(const std::string&, const std::string&) override { return {}; }
    security::RawPrivateKey GetPrikey() const override {
        static const char z = '\0';
        return {&z, 0u};
    }
    const std::string& GetAddress() const override { return addr_; }
    std::string GetAddress(const std::string&) override { return addr_; }
    const std::string& GetPublicKey() const override { return pubkey_; }
    const std::string& GetPublicKeyUnCompressed() const override { return pubkey_; }
    int Encrypt(const std::string&, security::RawPrivateKey, std::string*) override {
        return security::kSecurityError;
    }
    int Decrypt(const std::string&, security::RawPrivateKey, std::string*) override {
        return security::kSecurityError;
    }
    int GetEcdhKey(const std::string&, std::string*) override { return security::kSecurityError; }
    bool IsValidPublicKey(const std::string&) override { return false; }
    std::string UnicastAddress(const std::string& src) override { return src; }
    std::string GetSign(const std::string&, const std::string&, uint8_t) override { return {}; }

private:
    bool verify_ok_{false};
    std::string addr_;
    std::string pubkey_;
};

struct ScopedSecurityOverride {
    std::shared_ptr<security::Security>& slot;
    std::shared_ptr<security::Security> prev;
    explicit ScopedSecurityOverride(std::shared_ptr<security::Security>& s) : slot(s), prev(s) {}
    void emplace(std::shared_ptr<security::Security> neo) { slot = std::move(neo); }
    ~ScopedSecurityOverride() { slot = std::move(prev); }
};

struct ScopedAccountInfoOverride {
    std::function<std::shared_ptr<address::protobuf::AddressInfo>(const std::string&)> prev;
    explicit ScopedAccountInfoOverride(
            std::function<std::shared_ptr<address::protobuf::AddressInfo>(const std::string&)> fn) {
        prev = std::move(g_test_account_info_override);
        g_test_account_info_override = std::move(fn);
    }
    ~ScopedAccountInfoOverride() { g_test_account_info_override = std::move(prev); }
};

}  // namespace test
}  // namespace pools
}  // namespace seth
