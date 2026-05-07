#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "common/utils.h"
#include "dht/dht_key.h"
#include "dht/dht_proto.h"
#include "dht/dht_utils.h"
#include "transport/transport_utils.h"

#define private public
#include "common/global_info.h"
#undef private

namespace seth {
namespace dht {
namespace test {

namespace {

void SetGlobalInfoForDhtProto() {
    auto* g = common::GlobalInfo::Instance();
    g->config_public_ip_ = "203.0.113.10";
    g->set_config_local_port(6500);
}

dht::NodePtr MakeLocalNode(const std::string& public_ip) {
    return std::make_shared<dht::Node>(3, public_ip, 9100, "nonempty_pubkey", "node_id_proto");
}

}  // namespace

TEST(DhtProtoBranches, DefaultDhtSignCallbackReturnsSuccess) {
    std::string enc, ch, re;
    EXPECT_EQ(DefaultDhtSignCallback("peer", "append", &enc, &ch, &re), kDhtSuccess);
}

TEST(DhtProtoBranches, CreateBootstrapRequestFillsHeaderAndBody) {
    SetGlobalInfoForDhtProto();
    DhtKeyManager des(5u);
    transport::protobuf::Header msg;
    DhtProto::CreateBootstrapRequest(7, "local_pk", des.StrKey(), msg);
    EXPECT_EQ(msg.src_sharding_id(), 7);
    EXPECT_EQ(msg.des_dht_key(), des.StrKey());
    EXPECT_EQ(msg.type(), common::kDhtMessage);
    ASSERT_TRUE(msg.has_dht_proto());
    ASSERT_TRUE(msg.dht_proto().has_bootstrap_req());
    EXPECT_EQ(msg.dht_proto().bootstrap_req().pubkey(), "local_pk");
    EXPECT_EQ(msg.dht_proto().bootstrap_req().public_ip(), "203.0.113.10");
    EXPECT_EQ(msg.dht_proto().bootstrap_req().public_port(), 6500);
}

TEST(DhtProtoBranches, CreateBootstrapResponseFillsResponseFields) {
    SetGlobalInfoForDhtProto();
    DhtKeyManager des(8u);
    transport::protobuf::Header msg;
    transport::MessagePtr from;
    DhtProto::CreateBootstrapResponse(2, "pk2", des.StrKey(), from, msg);
    EXPECT_EQ(msg.src_sharding_id(), 2);
    EXPECT_EQ(msg.type(), common::kDhtMessage);
    ASSERT_TRUE(msg.dht_proto().has_bootstrap_res());
    EXPECT_EQ(msg.dht_proto().bootstrap_res().pubkey(), "pk2");
    EXPECT_EQ(msg.dht_proto().bootstrap_res().public_port(), 6500);
}

TEST(DhtProtoBranches, CreateRefreshNeighborsRequestBuildsBloomfilter) {
    SetGlobalInfoForDhtProto();
    Dht dht;
    auto a = std::make_shared<Node>(3, "203.0.113.1", 8001, "pk1", "id_a");
    auto b = std::make_shared<Node>(3, "203.0.113.2", 8002, "pk2", "id_b");
    dht.push_back(a);
    dht.push_back(b);

    NodePtr local = MakeLocalNode("203.0.113.3");
    DhtKeyManager des(3u);

    transport::protobuf::Header msg;
    DhtProto::CreateRefreshNeighborsRequest(dht, local, des.StrKey(), msg);
    ASSERT_TRUE(msg.has_dht_proto());
    ASSERT_TRUE(msg.dht_proto().has_refresh_neighbors_req());
    const auto& req = msg.dht_proto().refresh_neighbors_req();
    EXPECT_EQ(req.count(), kRefreshNeighborsDefaultCount);
    EXPECT_GT(req.bloomfilter_size(), 0u);
}

TEST(DhtProtoBranches, CreateRefreshNeighborsResponseCapsNodesAtDefaultCount) {
    SetGlobalInfoForDhtProto();
    DhtKeyManager des(4u);
    std::vector<NodePtr> nodes;
    for (int i = 0; i < 40; ++i) {
        std::string id = "nid_" + std::to_string(i);
        nodes.push_back(std::make_shared<Node>(
            1, "203.0.113." + std::to_string(i % 200 + 1), static_cast<uint16_t>(7000 + i), "pkx", id));
    }

    transport::protobuf::Header msg;
    DhtProto::CreateRefreshNeighborsResponse(9u, des.StrKey(), nodes, msg);
    ASSERT_TRUE(msg.dht_proto().has_refresh_neighbors_res());
    EXPECT_EQ(msg.dht_proto().refresh_neighbors_res().nodes_size(),
              static_cast<int>(kRefreshNeighborsDefaultCount));
}

TEST(DhtProtoBranches, CreateRefreshNeighborsResponseEmptyNodes) {
    DhtKeyManager des(11u);
    transport::protobuf::Header msg;
    DhtProto::CreateRefreshNeighborsResponse(1u, des.StrKey(), {}, msg);
    EXPECT_EQ(msg.dht_proto().refresh_neighbors_res().nodes_size(), 0);
}

TEST(DhtProtoBranches, CreateHeartbeatRequestAndResponse) {
    DhtKeyManager des(0u);
    NodePtr local = MakeLocalNode("203.0.113.20");
    NodePtr remote = MakeLocalNode("203.0.113.21");
    remote->dht_key = des.StrKey();

    transport::protobuf::Header req;
    DhtProto::CreateHeatbeatRequest(local, remote, req);
    EXPECT_EQ(req.type(), common::kDhtMessage);
    ASSERT_TRUE(req.dht_proto().has_heartbeat_req());
    EXPECT_EQ(req.dht_proto().heartbeat_req().dht_key_hash(), local->dht_key_hash);

    transport::protobuf::Header res;
    DhtProto::CreateHeatbeatResponse(local, des.StrKey(), res);
    ASSERT_TRUE(res.dht_proto().has_heartbeat_res());
    EXPECT_EQ(res.dht_proto().heartbeat_res().dht_key_hash(), local->dht_key_hash);
}

TEST(DhtProtoBranches, CreateConnectRequestRejectsVlanIp) {
    SetGlobalInfoForDhtProto();
    DhtKeyManager des(6u);
    NodePtr local = MakeLocalNode("192.168.1.5");
    transport::protobuf::Header msg;
    EXPECT_EQ(DhtProto::CreateConnectRequest(false, local, des.StrKey(), msg), kDhtError);
}

TEST(DhtProtoBranches, CreateConnectRequestSuccessForPublicIp) {
    SetGlobalInfoForDhtProto();
    DhtKeyManager des(6u);
    NodePtr local = MakeLocalNode("203.0.113.50");
    transport::protobuf::Header msg;
    EXPECT_EQ(DhtProto::CreateConnectRequest(true, local, des.StrKey(), msg), kDhtSuccess);
    ASSERT_TRUE(msg.dht_proto().has_connect_req());
    const auto& cr = msg.dht_proto().connect_req();
    EXPECT_TRUE(cr.is_response());
    EXPECT_EQ(cr.id(), local->id);
    EXPECT_EQ(cr.public_port(), 6500);
}

}  // namespace test
}  // namespace dht
}  // namespace seth
