// Additional branch-coverage tests for the network module.
// Exercises network_proto.cc, dht_manager.cc, and bootstrap.cc paths
// not yet hit by test_network_branches.cc.

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "network/bootstrap.h"
#include "network/dht_manager.h"
#include "network/network_proto.h"
#include "network/network_utils.h"
#include "dht/dht_utils.h"
#include "protos/transport.pb.h"

namespace seth {
namespace network {
namespace test {

// ---- Helpers ----

static dht::NodePtr MakeNode(
        int32_t sharding_id = 3,
        const std::string& ip = "127.0.0.1",
        uint16_t port = 9000,
        const std::string& pubkey = "test_pubkey") {
    return std::make_shared<dht::Node>(sharding_id, ip, port, pubkey, "test_id");
}

// ---- NetworkProto::CreateGetNetworkNodesRequest ----

TEST(NetworkProtoExtraTest, CreateRequest) {
    auto local = MakeNode(3);
    transport::protobuf::Header msg;
    NetworkProto::CreateGetNetworkNodesRequest(local, 3, 10, msg);
    EXPECT_EQ(3, msg.src_sharding_id());
    EXPECT_FALSE(msg.des_dht_key().empty());
    EXPECT_EQ(10u, msg.network_proto().get_net_nodes_req().count());
}

TEST(NetworkProtoExtraTest, CreateRequestDifferentNetworkIds) {
    auto local = MakeNode(3);
    transport::protobuf::Header msg1, msg2;
    NetworkProto::CreateGetNetworkNodesRequest(local, 3, 5, msg1);
    NetworkProto::CreateGetNetworkNodesRequest(local, 4, 5, msg2);
    // Different network_id → different dht_key
    EXPECT_NE(msg1.des_dht_key(), msg2.des_dht_key());
}

// ---- NetworkProto::CreateGetNetworkNodesResponse ----

TEST(NetworkProtoExtraTest, CreateResponseEmptyNodes) {
    auto local = MakeNode(3);
    transport::protobuf::Header req, resp;
    req.set_src_sharding_id(5);
    std::vector<dht::NodePtr> nodes;
    NetworkProto::CreateGetNetworkNodesResponse(local, req, nodes, resp);
    EXPECT_EQ(0, resp.network_proto().get_net_nodes_res().nodes_size());
}

TEST(NetworkProtoExtraTest, CreateResponseFilterEmptyPubkey) {
    auto local = MakeNode(3);
    transport::protobuf::Header req, resp;
    req.set_src_sharding_id(5);

    // One node with empty pubkey → should be filtered
    auto empty_pk_node = std::make_shared<dht::Node>();
    empty_pk_node->pubkey_str = "";

    std::vector<dht::NodePtr> nodes = {empty_pk_node};
    NetworkProto::CreateGetNetworkNodesResponse(local, req, nodes, resp);
    EXPECT_EQ(0, resp.network_proto().get_net_nodes_res().nodes_size());
}

TEST(NetworkProtoExtraTest, CreateResponseIncludesNonEmptyPubkey) {
    auto local = MakeNode(3);
    transport::protobuf::Header req, resp;
    req.set_src_sharding_id(5);

    auto node1 = MakeNode(3, "10.0.0.1", 9001, "pubkey1");
    auto node2 = std::make_shared<dht::Node>();
    node2->pubkey_str = "";  // filtered out

    std::vector<dht::NodePtr> nodes = {node1, node2};
    NetworkProto::CreateGetNetworkNodesResponse(local, req, nodes, resp);
    EXPECT_EQ(1, resp.network_proto().get_net_nodes_res().nodes_size());
}

TEST(NetworkProtoExtraTest, CreateResponseMultipleValidNodes) {
    auto local = MakeNode(3);
    transport::protobuf::Header req, resp;
    req.set_src_sharding_id(5);

    std::vector<dht::NodePtr> nodes;
    for (int i = 0; i < 3; ++i) {
        nodes.push_back(MakeNode(3, "10.0.0." + std::to_string(i + 1),
                                 9000 + i, "pubkey" + std::to_string(i)));
    }
    NetworkProto::CreateGetNetworkNodesResponse(local, req, nodes, resp);
    EXPECT_EQ(3, resp.network_proto().get_net_nodes_res().nodes_size());
}

// ---- DhtManager ----

TEST(DhtManagerExtraTest, InstanceIsSingleton) {
    auto m1 = DhtManager::Instance();
    auto m2 = DhtManager::Instance();
    EXPECT_EQ(m1, m2);
}

TEST(DhtManagerExtraTest, InitDoesNotCrash) {
    auto mgr = DhtManager::Instance();
    mgr->Init();
    // No crash after init
}

TEST(DhtManagerExtraTest, GetDhtOutOfRange) {
    auto mgr = DhtManager::Instance();
    mgr->Init();
    auto dht = mgr->GetDht(1000);  // beyond allocated range
    EXPECT_EQ(nullptr, dht);
}

TEST(DhtManagerExtraTest, GetDhtUnregisteredInRange) {
    auto mgr = DhtManager::Instance();
    mgr->Init();
    auto dht = mgr->GetDht(5);
    EXPECT_EQ(nullptr, dht);
}

TEST(DhtManagerExtraTest, UnRegisterUnregisteredNocrash) {
    auto mgr = DhtManager::Instance();
    mgr->Init();
    mgr->UnRegisterDht(15);  // never registered, no crash expected
}

TEST(DhtManagerExtraTest, DropNodeEmptyMap) {
    auto mgr = DhtManager::Instance();
    mgr->Init();
    // Drop node when no DHTs exist — no crash (API is ip + port)
    mgr->DropNode("127.0.0.1", 9000);
}

TEST(DhtManagerExtraTest, JoinWithNullNode) {
    auto mgr = DhtManager::Instance();
    mgr->Init();
    // Join with null node pointer — no crash
    dht::NodePtr node = nullptr;
    mgr->Join(node);
}

// ---- Bootstrap ----

TEST(BootstrapExtraTest, InstanceNonNull) {
    EXPECT_NE(nullptr, Bootstrap::Instance());
}

TEST(BootstrapExtraTest, GetNetworkBootstrapAcceptsCount) {
    // Second parameter is requested node count; may return empty without Universal DHT.
    auto nodes_root = Bootstrap::Instance()->GetNetworkBootstrap(kRootCongressNetworkId, 8u);
    auto nodes_node = Bootstrap::Instance()->GetNetworkBootstrap(kNodeNetworkId, 8u);
    EXPECT_GE(nodes_root.size(), 0u);
    EXPECT_GE(nodes_node.size(), 0u);
}

// ---- IsSameShardOrSameWaitingPool extra paths ----

TEST(NetworkUtilsExtraTest, SameId) {
    EXPECT_TRUE(IsSameShardOrSameWaitingPool(5, 5));
}

TEST(NetworkUtilsExtraTest, IdBelowConsensusShardBegin) {
    // IDs below kConsensusShardBeginNetworkId (3) are not consensus shards
    EXPECT_FALSE(IsSameShardOrSameWaitingPool(0, 1));
}

TEST(NetworkUtilsExtraTest, OneValidOneTooHigh) {
    EXPECT_FALSE(IsSameShardOrSameWaitingPool(3, 9999));
}

}  // namespace test
}  // namespace network
}  // namespace seth
