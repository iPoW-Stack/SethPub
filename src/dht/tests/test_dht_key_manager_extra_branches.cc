#include <gtest/gtest.h>

#include <string>

#include "dht/dht_key.h"

namespace shardora {
namespace dht {
namespace test {

TEST(DhtKeyManagerExtraBranches, RandomSeedCtorProducesFullSizeKey) {
    DhtKeyManager m(12345u);
    EXPECT_EQ(m.StrKey().size(), kDhtKeySize);
}

TEST(DhtKeyManagerExtraBranches, PubkeyCtorProducesFullSizeKey) {
    std::string pubkey(33, 'p');
    DhtKeyManager m(9u, pubkey);
    EXPECT_EQ(m.StrKey().size(), kDhtKeySize);
}

TEST(DhtKeyManagerExtraBranches, DhtKeyGetNetIdMatchesConstructedNetId) {
    constexpr uint32_t kNet = 404u;
    DhtKeyManager m(kNet);
    EXPECT_EQ(DhtKeyManager::DhtKeyGetNetId(m.StrKey()), kNet);
}

}  // namespace test
}  // namespace dht
}  // namespace shardora
