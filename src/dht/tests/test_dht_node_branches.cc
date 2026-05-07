#include <gtest/gtest.h>

#include <string>

#include "dht/dht_utils.h"

namespace seth {
namespace dht {
namespace test {

TEST(DhtNodeBranches, DefaultConstructClearsScalars) {
    Node n;
    EXPECT_EQ(n.id_hash, 0u);
    EXPECT_EQ(n.dht_key_hash, 0u);
    EXPECT_EQ(n.bucket, 0);
    EXPECT_EQ(n.public_port, 0);
    EXPECT_FALSE(n.first_node);
    EXPECT_EQ(n.join_way, static_cast<uint32_t>(kJoinFromUnknown));
    EXPECT_EQ(n.sharding_id, 0);
}

TEST(DhtNodeBranches, ParameterizedConstructCopiesFields) {
    Node n(7, "192.0.2.1", 9100, "pubkey_val", "node_id_ab");
    EXPECT_EQ(n.sharding_id, 7);
    EXPECT_EQ(n.public_ip, "192.0.2.1");
    EXPECT_EQ(n.public_port, 9100);
    EXPECT_EQ(n.pubkey_str, "pubkey_val");
    EXPECT_EQ(n.id, "node_id_ab");
}

TEST(DhtNodeBranches, AtomicsDefaultInitialized) {
    Node n;
    EXPECT_EQ(n.heartbeat_send_times.load(), 0u);
    EXPECT_EQ(n.heartbeat_alive_times.load(), kHeartbeatDefaultAliveTimes);
}

}  // namespace test
}  // namespace dht
}  // namespace seth
