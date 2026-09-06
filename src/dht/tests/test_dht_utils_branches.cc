#include <gtest/gtest.h>

#include <string>

#include "dht/dht_utils.h"

namespace shardora {
namespace dht {
namespace test {

TEST(DhtUtilsBranches, DefaultNodeConstructorKeepsDefaultFields) {
    Node node;
    EXPECT_EQ(node.id_hash, 0u);
    EXPECT_EQ(node.dht_key_hash, 0u);
    EXPECT_EQ(node.bucket, 0);
    EXPECT_EQ(node.heartbeat_times, 0);
    EXPECT_EQ(node.public_port, 0u);
    EXPECT_FALSE(node.first_node);
    EXPECT_EQ(node.join_way, static_cast<uint32_t>(kJoinFromUnknown));
    EXPECT_EQ(node.sharding_id, 0);
    EXPECT_TRUE(node.id.empty());
    EXPECT_TRUE(node.dht_key.empty());
    EXPECT_TRUE(node.public_ip.empty());
    EXPECT_TRUE(node.pubkey_str.empty());
}

TEST(DhtUtilsBranches, NodeConstructorInitializesHashesAndIdentityFields) {
    const std::string id = "node-id";
    const std::string ip = "127.0.0.1";
    const uint16_t port = 12345;
    const std::string pubkey = "pubkey";
    const int32_t shard = 7;

    Node node(shard, ip, port, pubkey, id);
    EXPECT_EQ(node.sharding_id, shard);
    EXPECT_EQ(node.public_ip, ip);
    EXPECT_EQ(node.public_port, port);
    EXPECT_EQ(node.pubkey_str, pubkey);
    EXPECT_EQ(node.id, id);
    EXPECT_FALSE(node.dht_key.empty());
    EXPECT_NE(node.id_hash, 0u);
    EXPECT_NE(node.dht_key_hash, 0u);
}

TEST(DhtUtilsBranches, DefaultDhtSignCallbackAlwaysReturnsSuccess) {
    std::string enc_data;
    std::string sign_ch;
    std::string sign_re;
    EXPECT_EQ(
        DefaultDhtSignCallback("peer_pub", "append", &enc_data, &sign_ch, &sign_re),
        kDhtSuccess);
    EXPECT_TRUE(enc_data.empty());
    EXPECT_TRUE(sign_ch.empty());
    EXPECT_TRUE(sign_re.empty());
}

TEST(DhtUtilsBranches, DefaultDhtSignCallbackAcceptsNullOutputPointers) {
    EXPECT_EQ(DefaultDhtSignCallback("peer_pub", "append", nullptr, nullptr, nullptr),
              kDhtSuccess);
}

TEST(DhtUtilsBranches, EnumAndConstantValuesRemainStable) {
    EXPECT_EQ(kDhtSuccess, 0);
    EXPECT_EQ(kDhtError, 1);
    EXPECT_EQ(kDhtKeyInvalidCountry, 13);

    EXPECT_EQ(kBootstrapNoInit, 0);
    EXPECT_EQ(kBootstrapInit, 1);
    EXPECT_EQ(kBootstrapInitWithConfNodes, 2);

    EXPECT_EQ(kNatTypeUnknown, 0);
    EXPECT_EQ(kNatTypeFullcone, 1);
    EXPECT_EQ(kNatTypeAddressLimit, 2);
    EXPECT_EQ(kNatTypePortLimit, 3);

    EXPECT_EQ(kDhtNearestNodesCount, 16u);
    EXPECT_EQ(kDhtMinReserveNodes, 4u);
    EXPECT_EQ(kDhtKeySize, 32u);
    EXPECT_EQ(kDhtMaxNeighbors, 1024u);
    EXPECT_EQ(kRefreshNeighborsCount, 32u);
    EXPECT_EQ(kRefreshNeighborsDefaultCount, 32u);
    EXPECT_EQ(kRefreshNeighborsBloomfilterBitCount, 4096u);
    EXPECT_EQ(kRefreshNeighborsBloomfilterHashCount, 11u);
    EXPECT_EQ(kHeartbeatDefaultAliveTimes, 3u);
}

TEST(DhtUtilsBranches, NodeJoinWayEnumOrderingAndRange) {
    EXPECT_EQ(kJoinFromUnknown, 0);
    EXPECT_EQ(kJoinFromBootstrapRes, 1);
    EXPECT_EQ(kJoinFromRefreshNeigberRequest, 2);
    EXPECT_EQ(kJoinFromRefreshNeigberResponse, 3);
    EXPECT_EQ(kJoinFromElectBlock, 4);
    EXPECT_EQ(kJoinFromNetworkDetection, 5);
    EXPECT_EQ(kJoinFromBootstrapReq, 6);
    EXPECT_EQ(kJoinFromConnect, 7);
    EXPECT_EQ(kJoinFromDetection, 8);
    EXPECT_EQ(kJoinFromUniversal, 9);
    EXPECT_EQ(kJoinFromInit, 10);
}

TEST(DhtUtilsBranches, NodeAtomicHeartbeatCountersHaveExpectedDefaults) {
    Node node;
    EXPECT_EQ(node.heartbeat_send_times.load(), 0u);
    EXPECT_EQ(node.heartbeat_alive_times.load(), kHeartbeatDefaultAliveTimes);
}

TEST(DhtUtilsBranches, NodeConstructorDependsOnShardingIdAndIdForDhtKey) {
    const std::string ip = "127.0.0.1";
    const uint16_t port = 12345;
    const std::string pubkey = "pubkey";
    const std::string id = "same-id";
    Node a(1, ip, port, pubkey, id);
    Node b(2, ip, port, pubkey, id);
    EXPECT_EQ(a.id_hash, b.id_hash);  // same id
    EXPECT_NE(a.dht_key, b.dht_key);  // shard participates in DHT key derivation
    EXPECT_NE(a.dht_key_hash, b.dht_key_hash);
}

}  // namespace test
}  // namespace dht
}  // namespace shardora
#include <gtest/gtest.h>

#include "dht/dht_utils.h"

namespace shardora {
namespace dht {
namespace test {

TEST(DhtUtilsBranches, DhtErrorCodeEnumComplete) {
    EXPECT_EQ(kDhtSuccess, 0);
    EXPECT_EQ(kDhtError, 1);
    EXPECT_EQ(kDhtInvalidNat, 2);
    EXPECT_EQ(kDhtNodeJoined, 3);
    EXPECT_EQ(kDhtInvalidBucket, 4);
    EXPECT_EQ(kDhtDesInvalid, 5);
    EXPECT_EQ(kDhtIpInvalid, 6);
    EXPECT_EQ(kDhtKeyInvalid, 7);
    EXPECT_EQ(kDhtClientMode, 8);
    EXPECT_EQ(kNodeInvalid, 9);
    EXPECT_EQ(kDhtKeyHashError, 10);
    EXPECT_EQ(kDhtGetBucketError, 11);
    EXPECT_EQ(kDhtMaxNeiborsError, 12);
    EXPECT_EQ(kDhtKeyInvalidCountry, 13);
}

TEST(DhtUtilsBranches, BootstrapTagValues) {
    EXPECT_EQ(kBootstrapNoInit, 0);
    EXPECT_EQ(kBootstrapInit, 1);
    EXPECT_EQ(kBootstrapInitWithConfNodes, 2);
}

TEST(DhtUtilsBranches, NatTypeOrdered) {
    EXPECT_LT(static_cast<int>(kNatTypeUnknown), static_cast<int>(kNatTypeFullcone));
    EXPECT_LT(static_cast<int>(kNatTypeFullcone), static_cast<int>(kNatTypeAddressLimit));
    EXPECT_LT(static_cast<int>(kNatTypeAddressLimit), static_cast<int>(kNatTypePortLimit));
}

TEST(DhtUtilsBranches, NodeJoinWayStartsAtUnknown) {
    EXPECT_EQ(kJoinFromUnknown, 0);
}

TEST(DhtUtilsBranches, NodeJoinWayEnumSequential) {
    EXPECT_EQ(kJoinFromUnknown, 0);
    EXPECT_EQ(kJoinFromBootstrapRes, 1);
    EXPECT_EQ(kJoinFromRefreshNeigberRequest, 2);
    EXPECT_EQ(kJoinFromRefreshNeigberResponse, 3);
    EXPECT_EQ(kJoinFromElectBlock, 4);
    EXPECT_EQ(kJoinFromNetworkDetection, 5);
    EXPECT_EQ(kJoinFromBootstrapReq, 6);
    EXPECT_EQ(kJoinFromConnect, 7);
    EXPECT_EQ(kJoinFromDetection, 8);
    EXPECT_EQ(kJoinFromUniversal, 9);
    EXPECT_EQ(kJoinFromInit, 10);
}

TEST(DhtUtilsBranches, RefreshNeighborCountsConsistent) {
    EXPECT_EQ(kRefreshNeighborsDefaultCount, kRefreshNeighborsCount);
    EXPECT_GT(kRefreshNeighborsBloomfilterBitCount, 0u);
    EXPECT_GT(kRefreshNeighborsBloomfilterHashCount, 0u);
}

TEST(DhtUtilsBranches, DhtScaleConstantsOrdered) {
    EXPECT_GT(kDhtNearestNodesCount, 0u);
    EXPECT_GT(kDhtMinReserveNodes, 0u);
    EXPECT_EQ(kDhtKeySize, 32u);
    EXPECT_GT(kDhtMaxNeighbors, kDhtNearestNodesCount);
}

}  // namespace test
}  // namespace dht
}  // namespace shardora
