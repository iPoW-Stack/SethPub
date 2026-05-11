#include <gtest/gtest.h>

#include <string>
#include <set>

#include "common/random.h"
#include "common/hash.h"
#include "common/encode.h"
#include "dht/dht_key.h"
#include "dht/dht_utils.h"

namespace seth {

namespace dht {

namespace test {

class TestDhtKey : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- Construction from network ID ---

TEST_F(TestDhtKey, ConstructFromNetId) {
    uint32_t net_id = 3;
    DhtKeyManager key(net_id);
    ASSERT_EQ(key.StrKey().size(), kDhtKeySize);

    // Verify network ID is embedded
    uint32_t extracted_id = DhtKeyManager::DhtKeyGetNetId(key.StrKey());
    ASSERT_EQ(extracted_id, net_id);
}

TEST_F(TestDhtKey, ConstructFromNetIdZero) {
    DhtKeyManager key(0u);
    ASSERT_EQ(key.StrKey().size(), kDhtKeySize);
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key.StrKey()), 0u);
}

TEST_F(TestDhtKey, ConstructFromNetIdLarge) {
    uint32_t net_id = 0xFFFFFFFF;
    DhtKeyManager key(net_id);
    ASSERT_EQ(key.StrKey().size(), kDhtKeySize);
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key.StrKey()), net_id);
}

TEST_F(TestDhtKey, ConstructFromNetIdUnique) {
    // Two keys with same net_id should differ (random hash part)
    DhtKeyManager key1(5u);
    DhtKeyManager key2(5u);
    ASSERT_EQ(key1.StrKey().size(), kDhtKeySize);
    ASSERT_EQ(key2.StrKey().size(), kDhtKeySize);
    // Same net_id
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key1.StrKey()), 5u);
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key2.StrKey()), 5u);
    // But different keys (extremely unlikely to collide)
    ASSERT_NE(key1.StrKey(), key2.StrKey());
}

// --- Construction from network ID + pubkey ---

TEST_F(TestDhtKey, ConstructFromNetIdAndPubkey) {
    uint32_t net_id = 7;
    std::string pubkey = common::Random::RandomString(33);
    DhtKeyManager key(net_id, pubkey);
    ASSERT_EQ(key.StrKey().size(), kDhtKeySize);
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key.StrKey()), net_id);
}

TEST_F(TestDhtKey, ConstructFromNetIdAndPubkeyDeterministic) {
    uint32_t net_id = 10;
    std::string pubkey = "fixed_pubkey_for_determinism_test";
    DhtKeyManager key1(net_id, pubkey);
    DhtKeyManager key2(net_id, pubkey);
    // Same inputs should produce same key
    ASSERT_EQ(key1.StrKey(), key2.StrKey());
}

TEST_F(TestDhtKey, ConstructFromNetIdAndPubkeyDifferentPubkeys) {
    uint32_t net_id = 10;
    std::string pubkey1 = "pubkey_alice";
    std::string pubkey2 = "pubkey_bob";
    DhtKeyManager key1(net_id, pubkey1);
    DhtKeyManager key2(net_id, pubkey2);
    // Different pubkeys should produce different keys
    ASSERT_NE(key1.StrKey(), key2.StrKey());
}

TEST_F(TestDhtKey, ConstructFromNetIdAndPubkeyDifferentNetIds) {
    std::string pubkey = "same_pubkey";
    DhtKeyManager key1(3, pubkey);
    DhtKeyManager key2(4, pubkey);
    // Different net_ids should produce different keys
    ASSERT_NE(key1.StrKey(), key2.StrKey());
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key1.StrKey()), 3u);
    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key2.StrKey()), 4u);
}

// --- Construction from raw string ---

TEST_F(TestDhtKey, ConstructFromString) {
    std::string raw_key(kDhtKeySize, '\x42');
    DhtKeyManager key(raw_key);
    ASSERT_EQ(key.StrKey(), raw_key);
    ASSERT_EQ(key.StrKey().size(), kDhtKeySize);
}

// --- DhtKeyGetNetId ---

TEST_F(TestDhtKey, GetNetIdFromKey) {
    // Manually construct a key with known net_id
    std::string key(kDhtKeySize, '\0');
    uint32_t net_id = 12345;
    memcpy(&key[0], &net_id, sizeof(net_id));

    ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key), net_id);
}

TEST_F(TestDhtKey, GetNetIdVariousValues) {
    std::vector<uint32_t> net_ids = {0, 1, 2, 3, 100, 1000, 65535, 0xFFFF, 0xFFFFFFFF};
    for (auto id : net_ids) {
        DhtKeyManager key(id);
        ASSERT_EQ(DhtKeyManager::DhtKeyGetNetId(key.StrKey()), id)
            << "Failed for net_id: " << id;
    }
}

}  // namespace test

}  // namespace dht

}  // namespace seth
