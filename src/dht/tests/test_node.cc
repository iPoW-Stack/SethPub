#include <gtest/gtest.h>

#include <string>

#include "common/random.h"
#include "common/hash.h"
#include "dht/dht_utils.h"
#include "dht/dht_key.h"

namespace shardora {

namespace dht {

namespace test {

class TestNode : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- Default Construction ---

TEST_F(TestNode, DefaultConstruction) {
    Node node;
    ASSERT_EQ(node.id_hash, 0u);
    ASSERT_EQ(node.dht_key_hash, 0u);
    ASSERT_EQ(node.bucket, 0);
    ASSERT_EQ(node.heartbeat_times, 0);
    ASSERT_EQ(node.public_port, 0u);
    ASSERT_FALSE(node.first_node);
    ASSERT_EQ(node.join_way, (uint32_t)kJoinFromUnknown);
    ASSERT_EQ(node.sharding_id, 0);
    ASSERT_TRUE(node.id.empty());
    ASSERT_TRUE(node.dht_key.empty());
    ASSERT_TRUE(node.public_ip.empty());
    ASSERT_TRUE(node.pubkey_str.empty());
}

// --- Parameterized Construction ---

TEST_F(TestNode, ParameterizedConstruction) {
    int32_t sharding_id = 3;
    std::string ip = "192.168.1.100";
    uint16_t port = 9001;
    std::string pubkey = common::Random::RandomString(33);
    std::string id = common::Random::RandomString(20);

    Node node(sharding_id, ip, port, pubkey, id);

    ASSERT_EQ(node.sharding_id, sharding_id);
    ASSERT_EQ(node.public_ip, ip);
    ASSERT_EQ(node.public_port, port);
    ASSERT_EQ(node.pubkey_str, pubkey);
    ASSERT_EQ(node.id, id);
    ASSERT_EQ(node.dht_key.size(), kDhtKeySize);
    ASSERT_NE(node.id_hash, 0u);
    ASSERT_NE(node.dht_key_hash, 0u);
}

TEST_F(TestNode, DhtKeyDerivedFromId) {
    std::string id = "test_node_id_12345";
    Node node(3, "10.0.0.1", 8000, "pubkey_data_33bytes_placeholder!", id);

    // DHT key should be deterministic for same sharding_id + id
    DhtKeyManager expected_key(3, id);
    ASSERT_EQ(node.dht_key, expected_key.StrKey());
}

TEST_F(TestNode, DhtKeyNetworkIdEmbedded) {
    int32_t sharding_id = 7;
    Node node(sharding_id, "10.0.0.1", 8000, "pubkey_placeholder_33bytes_long!", "node_id");

    uint32_t extracted_net_id = DhtKeyManager::DhtKeyGetNetId(node.dht_key);
    ASSERT_EQ(extracted_net_id, (uint32_t)sharding_id);
}

TEST_F(TestNode, IdHashConsistency) {
    std::string id = "consistent_id";
    Node node(3, "10.0.0.1", 8000, "pubkey_placeholder_33bytes_long!", id);

    uint64_t expected_hash = common::Hash::Hash64(id);
    ASSERT_EQ(node.id_hash, expected_hash);
}

TEST_F(TestNode, DhtKeyHashConsistency) {
    std::string id = "hash_test_id";
    Node node(3, "10.0.0.1", 8000, "pubkey_placeholder_33bytes_long!", id);

    uint64_t expected_hash = common::Hash::Hash64(node.dht_key);
    ASSERT_EQ(node.dht_key_hash, expected_hash);
}

// --- Heartbeat Tests ---

TEST_F(TestNode, HeartbeatDefaults) {
    Node node;
    ASSERT_EQ(node.heartbeat_send_times.load(), 0u);
    ASSERT_EQ(node.heartbeat_alive_times.load(), kHeartbeatDefaultAliveTimes);
}

TEST_F(TestNode, HeartbeatAtomic) {
    Node node;
    node.heartbeat_send_times++;
    node.heartbeat_send_times++;
    ASSERT_EQ(node.heartbeat_send_times.load(), 2u);

    node.heartbeat_alive_times--;
    ASSERT_EQ(node.heartbeat_alive_times.load(), kHeartbeatDefaultAliveTimes - 1);
}

// --- NodePtr Tests ---

TEST_F(TestNode, SharedPtrUsage) {
    NodePtr node = std::make_shared<Node>(
        3, "10.0.0.1", 8000, "pubkey_placeholder_33bytes_long!", "shared_node");
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->public_ip, "10.0.0.1");
    ASSERT_EQ(node->public_port, 8000u);
}

// --- Error Code Tests ---

TEST_F(TestNode, ErrorCodes) {
    ASSERT_EQ(kDhtSuccess, 0);
    ASSERT_EQ(kDhtError, 1);
    ASSERT_NE(kDhtSuccess, kDhtError);
    ASSERT_NE(kDhtNodeJoined, kDhtSuccess);
}

// --- Constants Tests ---

TEST_F(TestNode, Constants) {
    ASSERT_EQ(kDhtKeySize, 32u);
    ASSERT_GT(kDhtMaxNeighbors, 0u);
    ASSERT_GT(kDhtNearestNodesCount, 0u);
    ASSERT_LE(kDhtNearestNodesCount, kDhtMaxNeighbors);
}

}  // namespace test

}  // namespace dht

}  // namespace shardora
