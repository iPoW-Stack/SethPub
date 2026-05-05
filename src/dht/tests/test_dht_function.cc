#include <gtest/gtest.h>

#include <string>
#include <vector>
#include <set>
#include <algorithm>

#include "common/random.h"
#include "common/hash.h"
#include "common/encode.h"
#include "dht/dht_function.h"
#include "dht/dht_key.h"
#include "dht/dht_utils.h"

namespace seth {

namespace dht {

namespace test {

class TestDhtFunction : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

protected:
    // Helper to create a node with a specific dht_key
    NodePtr MakeNode(const std::string& dht_key, uint32_t sharding_id = 3) {
        auto node = std::make_shared<Node>();
        node->dht_key = dht_key;
        node->dht_key_hash = common::Hash::Hash64(dht_key);
        node->id = common::Random::RandomString(20);
        node->id_hash = common::Hash::Hash64(node->id);
        node->public_ip = "127.0.0.1";
        node->public_port = 8000;
        node->sharding_id = sharding_id;
        node->bucket = 0;
        return node;
    }

    // Helper to create a node with a random key for a given network
    NodePtr MakeRandomNode(uint32_t net_id = 3) {
        DhtKeyManager key_mgr(net_id);
        return MakeNode(key_mgr.StrKey(), net_id);
    }
};

// --- CloserToTarget Tests ---

TEST_F(TestDhtFunction, CloserToTargetBasic) {
    std::string target(kDhtKeySize, '\x00');
    target[31] = '\x10';  // target = ...0x10

    std::string closer(kDhtKeySize, '\x00');
    closer[31] = '\x11';  // XOR distance = 0x01

    std::string farther(kDhtKeySize, '\x00');
    farther[31] = '\x30';  // XOR distance = 0x20

    ASSERT_TRUE(DhtFunction::CloserToTarget(closer, farther, target));
    ASSERT_FALSE(DhtFunction::CloserToTarget(farther, closer, target));
}

TEST_F(TestDhtFunction, CloserToTargetEqual) {
    std::string target(kDhtKeySize, '\x42');
    std::string same(kDhtKeySize, '\x42');
    // Same distance to target (both are the target itself)
    ASSERT_FALSE(DhtFunction::CloserToTarget(same, same, target));
}

TEST_F(TestDhtFunction, CloserToTargetSelf) {
    std::string target(kDhtKeySize, '\xAB');
    std::string other(kDhtKeySize, '\x00');
    // Target is closest to itself (XOR distance = 0)
    ASSERT_TRUE(DhtFunction::CloserToTarget(target, other, target));
}

TEST_F(TestDhtFunction, CloserToTargetSymmetry) {
    std::string target(kDhtKeySize, '\x50');
    std::string a(kDhtKeySize, '\x51');
    std::string b(kDhtKeySize, '\x70');

    // If a is closer than b, then b is NOT closer than a
    bool a_closer = DhtFunction::CloserToTarget(a, b, target);
    bool b_closer = DhtFunction::CloserToTarget(b, a, target);
    ASSERT_NE(a_closer, b_closer);
}

TEST_F(TestDhtFunction, CloserToTargetTransitive) {
    std::string target(kDhtKeySize, '\x00');

    std::string a(kDhtKeySize, '\x00');
    a[31] = '\x01';  // distance 1

    std::string b(kDhtKeySize, '\x00');
    b[31] = '\x02';  // distance 2

    std::string c(kDhtKeySize, '\x00');
    c[31] = '\x04';  // distance 4

    // a closer than b, b closer than c => a closer than c
    ASSERT_TRUE(DhtFunction::CloserToTarget(a, b, target));
    ASSERT_TRUE(DhtFunction::CloserToTarget(b, c, target));
    ASSERT_TRUE(DhtFunction::CloserToTarget(a, c, target));
}

// --- GetDhtBucket Tests ---

TEST_F(TestDhtFunction, GetDhtBucketDifferentFirstBit) {
    std::string src_key(kDhtKeySize, '\x00');
    auto node = MakeNode(std::string(kDhtKeySize, '\x80'));  // First bit differs

    int result = DhtFunction::GetDhtBucket(src_key, node);
    ASSERT_EQ(result, kDhtSuccess);
    // Bucket should be high (first bit difference = bucket 255)
    ASSERT_EQ(node->bucket, 255);
}

TEST_F(TestDhtFunction, GetDhtBucketDifferentLastBit) {
    std::string src_key(kDhtKeySize, '\x00');
    auto node = MakeNode(std::string(kDhtKeySize, '\x00'));
    // Only last bit of last byte differs
    node->dht_key[31] = '\x01';

    int result = DhtFunction::GetDhtBucket(src_key, node);
    ASSERT_EQ(result, kDhtSuccess);
    ASSERT_EQ(node->bucket, 0);  // Lowest bucket
}

TEST_F(TestDhtFunction, GetDhtBucketSameKey) {
    std::string src_key(kDhtKeySize, '\xAB');
    auto node = MakeNode(std::string(kDhtKeySize, '\xAB'));

    int result = DhtFunction::GetDhtBucket(src_key, node);
    ASSERT_EQ(result, kDhtError);
    ASSERT_EQ(node->bucket, -1);
}

TEST_F(TestDhtFunction, GetDhtBucketRange) {
    std::string src_key(kDhtKeySize, '\x00');

    // Test various bucket positions
    for (int byte_idx = 0; byte_idx < (int)kDhtKeySize; ++byte_idx) {
        for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
            std::string node_key(kDhtKeySize, '\x00');
            node_key[byte_idx] = (char)(1 << (7 - bit_idx));
            auto node = MakeNode(node_key);

            int result = DhtFunction::GetDhtBucket(src_key, node);
            ASSERT_EQ(result, kDhtSuccess);
            int expected_bucket = (8 * (kDhtKeySize - byte_idx)) - bit_idx - 1;
            ASSERT_EQ(node->bucket, expected_bucket)
                << "byte_idx=" << byte_idx << " bit_idx=" << bit_idx;
        }
    }
}

// --- PartialSort Tests ---

TEST_F(TestDhtFunction, PartialSortBasic) {
    std::string target(kDhtKeySize, '\x00');
    target[31] = '\x10';

    Dht dht;
    // Create nodes at various distances
    for (int i = 0; i < 10; ++i) {
        std::string key(kDhtKeySize, '\x00');
        key[31] = (char)(0x10 + i + 1);  // Increasing XOR distance from target
        dht.push_back(MakeNode(key));
    }

    // Shuffle to randomize order
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(dht.begin(), dht.end(), g);

    uint32_t sorted = DhtFunction::PartialSort(target, 5, dht);
    ASSERT_EQ(sorted, 5u);

    // First 5 should be sorted by distance to target
    for (uint32_t i = 0; i < sorted - 1; ++i) {
        ASSERT_TRUE(DhtFunction::CloserToTarget(
            dht[i]->dht_key, dht[i + 1]->dht_key, target));
    }
}

TEST_F(TestDhtFunction, PartialSortEmptyDht) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    uint32_t sorted = DhtFunction::PartialSort(target, 5, dht);
    ASSERT_EQ(sorted, 0u);
}

TEST_F(TestDhtFunction, PartialSortCountExceedsDhtSize) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    dht.push_back(MakeRandomNode());
    dht.push_back(MakeRandomNode());

    uint32_t sorted = DhtFunction::PartialSort(target, 100, dht);
    ASSERT_EQ(sorted, 2u);
}

// --- GetClosestNode Tests ---

TEST_F(TestDhtFunction, GetClosestNodeBasic) {
    std::string target(kDhtKeySize, '\x00');
    target[31] = '\x10';

    Dht dht;
    std::string close_key(kDhtKeySize, '\x00');
    close_key[31] = '\x11';  // distance 1
    dht.push_back(MakeNode(close_key));

    std::string far_key(kDhtKeySize, '\x00');
    far_key[31] = '\xFF';  // distance large
    dht.push_back(MakeNode(far_key));

    auto closest = DhtFunction::GetClosestNode(dht, target);
    ASSERT_NE(closest, nullptr);
    ASSERT_EQ(closest->dht_key, close_key);
}

TEST_F(TestDhtFunction, GetClosestNodeSingleElement) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    auto node = MakeRandomNode();
    dht.push_back(node);

    auto closest = DhtFunction::GetClosestNode(dht, target);
    ASSERT_NE(closest, nullptr);
    ASSERT_EQ(closest->dht_key, node->dht_key);
}

TEST_F(TestDhtFunction, GetClosestNodeEmpty) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    auto closest = DhtFunction::GetClosestNode(dht, target);
    ASSERT_EQ(closest, nullptr);
}

// --- GetClosestNodes Tests ---

TEST_F(TestDhtFunction, GetClosestNodesBasic) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    for (int i = 0; i < 20; ++i) {
        dht.push_back(MakeRandomNode());
    }

    auto closest = DhtFunction::GetClosestNodes(dht, target, 5);
    ASSERT_EQ(closest.size(), 5u);

    // Verify they are sorted by distance
    for (size_t i = 0; i < closest.size() - 1; ++i) {
        ASSERT_TRUE(DhtFunction::CloserToTarget(
            closest[i]->dht_key, closest[i + 1]->dht_key, target));
    }
}

TEST_F(TestDhtFunction, GetClosestNodesZeroCount) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    dht.push_back(MakeRandomNode());

    auto closest = DhtFunction::GetClosestNodes(dht, target, 0);
    ASSERT_TRUE(closest.empty());
}

TEST_F(TestDhtFunction, GetClosestNodesEmptyDht) {
    std::string target(kDhtKeySize, '\x00');
    Dht dht;
    auto closest = DhtFunction::GetClosestNodes(dht, target, 5);
    ASSERT_TRUE(closest.empty());
}

// --- GetNetworkNodes Tests ---

TEST_F(TestDhtFunction, GetNetworkNodesBasic) {
    Dht dht;
    // Add nodes from different networks
    for (int i = 0; i < 5; ++i) {
        dht.push_back(MakeRandomNode(3));  // network 3
    }
    for (int i = 0; i < 3; ++i) {
        dht.push_back(MakeRandomNode(4));  // network 4
    }
    for (int i = 0; i < 2; ++i) {
        dht.push_back(MakeRandomNode(5));  // network 5
    }

    std::vector<NodePtr> net3_nodes;
    DhtFunction::GetNetworkNodes(dht, 3, net3_nodes);
    ASSERT_EQ(net3_nodes.size(), 5u);

    std::vector<NodePtr> net4_nodes;
    DhtFunction::GetNetworkNodes(dht, 4, net4_nodes);
    ASSERT_EQ(net4_nodes.size(), 3u);

    std::vector<NodePtr> net5_nodes;
    DhtFunction::GetNetworkNodes(dht, 5, net5_nodes);
    ASSERT_EQ(net5_nodes.size(), 2u);
}

TEST_F(TestDhtFunction, GetNetworkNodesNoMatch) {
    Dht dht;
    dht.push_back(MakeRandomNode(3));
    dht.push_back(MakeRandomNode(4));

    std::vector<NodePtr> nodes;
    DhtFunction::GetNetworkNodes(dht, 99, nodes);
    ASSERT_TRUE(nodes.empty());
}

TEST_F(TestDhtFunction, GetNetworkNodesEmpty) {
    Dht dht;
    std::vector<NodePtr> nodes;
    DhtFunction::GetNetworkNodes(dht, 3, nodes);
    ASSERT_TRUE(nodes.empty());
}

// --- IsClosest Tests ---

TEST_F(TestDhtFunction, IsClosestWhenActuallyClosest) {
    std::string target(kDhtKeySize, '\x00');
    target[31] = '\x10';

    // Local key is very close to target
    std::string local_key(kDhtKeySize, '\x00');
    local_key[31] = '\x11';  // distance 1

    Dht dht;
    // Other nodes are farther
    for (int i = 0; i < 5; ++i) {
        std::string key(kDhtKeySize, '\x00');
        key[31] = (char)(0x10 + 0x20 + i);  // distance > 1
        auto node = MakeNode(key);
        node->bucket = 1;  // non-zero bucket
        dht.push_back(node);
    }

    bool closest = false;
    int result = DhtFunction::IsClosest(target, local_key, dht, closest);
    ASSERT_EQ(result, kDhtSuccess);
    ASSERT_TRUE(closest);
}

TEST_F(TestDhtFunction, IsClosestWhenNotClosest) {
    std::string target(kDhtKeySize, '\x00');
    target[31] = '\x10';

    // Local key is far from target
    std::string local_key(kDhtKeySize, '\xFF');

    Dht dht;
    // Add a node that is closer
    std::string close_key(kDhtKeySize, '\x00');
    close_key[31] = '\x11';  // distance 1 from target
    auto close_node = MakeNode(close_key);
    close_node->bucket = 1;
    dht.push_back(close_node);

    bool closest = false;
    int result = DhtFunction::IsClosest(target, local_key, dht, closest);
    ASSERT_EQ(result, kDhtSuccess);
    ASSERT_FALSE(closest);
}

TEST_F(TestDhtFunction, IsClosestSameAsTarget) {
    std::string target(kDhtKeySize, '\x42');
    std::string local_key = target;  // Same as target

    Dht dht;
    dht.push_back(MakeRandomNode());

    bool closest = false;
    int result = DhtFunction::IsClosest(target, local_key, dht, closest);
    ASSERT_EQ(result, kDhtError);  // target == local is an error
}

TEST_F(TestDhtFunction, IsClosestInvalidKeySize) {
    std::string target = "short";
    std::string local_key(kDhtKeySize, '\x00');

    Dht dht;
    dht.push_back(MakeRandomNode());

    bool closest = false;
    int result = DhtFunction::IsClosest(target, local_key, dht, closest);
    ASSERT_EQ(result, kDhtError);
}

// --- Displacement Tests ---

TEST_F(TestDhtFunction, DisplacementWhenNotFull) {
    std::string local_key(kDhtKeySize, '\x00');
    Dht dht;
    // DHT is not full (< kDhtMaxNeighbors)
    for (uint32_t i = 0; i < 10; ++i) {
        dht.push_back(MakeRandomNode());
    }

    auto new_node = MakeRandomNode();
    new_node->bucket = 5;
    uint32_t replace_pos = 0;
    bool should_add = DhtFunction::Displacement(local_key, dht, new_node, replace_pos);
    ASSERT_TRUE(should_add);
}

}  // namespace test

}  // namespace dht

}  // namespace seth
