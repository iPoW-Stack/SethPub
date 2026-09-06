#include <gtest/gtest.h>

#include <string>

#include "dht/dht_key.h"

namespace shardora {
namespace dht {
namespace test {

TEST(DhtKeyManagerBranches, RandomConstructorPreservesNetIdInKey) {
    constexpr uint32_t kNet = 424242u;
    DhtKeyManager m(kNet);
    ASSERT_FALSE(m.StrKey().empty());
    EXPECT_EQ(DhtKeyManager::DhtKeyGetNetId(m.StrKey()), kNet);
}

TEST(DhtKeyManagerBranches, PubkeyConstructorPreservesNetId) {
    constexpr uint32_t kNet = 7u;
    const std::string pubkey(128, 'p');
    DhtKeyManager m(kNet, pubkey);
    ASSERT_FALSE(m.StrKey().empty());
    EXPECT_EQ(DhtKeyManager::DhtKeyGetNetId(m.StrKey()), kNet);
}

TEST(DhtKeyManagerBranches, StrKeyStableAcrossCalls) {
    DhtKeyManager m(99u);
    EXPECT_EQ(m.StrKey(), m.StrKey());
}

TEST(DhtKeyManagerBranches, FromBinaryKeyRoundTripsNetId) {
    constexpr uint32_t kNet = 55u;
    DhtKeyManager origin(kNet);
    const std::string key = origin.StrKey();
    DhtKeyManager from_key(key);
    EXPECT_EQ(from_key.StrKey(), key);
    EXPECT_EQ(DhtKeyManager::DhtKeyGetNetId(from_key.StrKey()), kNet);
}

}  // namespace test
}  // namespace dht
}  // namespace shardora
