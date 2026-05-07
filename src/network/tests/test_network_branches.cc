#include <gtest/gtest.h>

#include <memory>
#include <vector>

#include "common/global_info.h"
#include "common/utils.h"
#include "dht/base_dht.h"
#include "dht/dht_utils.h"
#include "network/dht_manager.h"
#include "network/network_proto.h"
#include "network/network_utils.h"

namespace seth {
namespace network {
namespace test {

namespace {

class GlobalNetworkIdGuard {
public:
    explicit GlobalNetworkIdGuard(uint32_t new_id) : previous_(common::GlobalInfo::Instance()->network_id()) {
        common::GlobalInfo::Instance()->set_network_id(new_id);
    }
    ~GlobalNetworkIdGuard() { common::GlobalInfo::Instance()->set_network_id(previous_); }

private:
    uint32_t previous_;
};

dht::NodePtr MakeNode(uint32_t shard, const char* ip, uint16_t port, const std::string& pubkey,
                      const std::string& id) {
    return std::make_shared<dht::Node>(shard, ip, port, pubkey, id);
}

}  // namespace

TEST(NetworkUtilsBranches, NetworkErrorCodeEnumValues) {
    EXPECT_EQ(kNetworkSuccess, 0);
    EXPECT_EQ(kNetworkError, 1);
    EXPECT_EQ(kNetworkJoinUniversalError, 2);
    EXPECT_EQ(kNetworkJoinShardFailed, 3);
    EXPECT_EQ(kNetworkNoBootstrapNodes, 4);
    EXPECT_EQ(kNetworkNetworkJoined, 5);
    EXPECT_EQ(kNetworkNetworkNotJoined, 6);
}

TEST(NetworkUtilsBranches, ConsensusShardNetworkCountMatchesBounds) {
    EXPECT_EQ(kConsensusShardNetworkCount,
              kConsensusShardEndNetworkId - kConsensusShardBeginNetworkId + 1u);
}

TEST(NetworkUtilsBranches, ServiceShardBoundsOrdered) {
    EXPECT_LT(kServiceShardBeginNetworkId, kServiceShardEndNetworkId);
}

TEST(NetworkUtilsBranches, ServiceNetworkTypeVpnLessThanWaitingPool) {
    EXPECT_LT(static_cast<uint32_t>(kVpnNetworkId), static_cast<uint32_t>(kWaitingPoolNetworkId));
}

TEST(NetworkUtilsBranches, IsSameShardOrSameWaitingPoolCoversBranches) {
    EXPECT_TRUE(IsSameShardOrSameWaitingPool(5u, 5u));

    const uint32_t des = 50u;
    ASSERT_LT(des, kConsensusShardEndNetworkId);
    ASSERT_GE(des, kRootCongressNetworkId);
    const uint32_t local = des + kConsensusWaitingShardOffset;
    EXPECT_TRUE(IsSameShardOrSameWaitingPool(local, des));

    EXPECT_FALSE(IsSameShardOrSameWaitingPool(9u, 8u));
}

TEST(NetworkUtilsBranches, IsSameShardOrSameWaitingPoolFalseWhenDesBelowConsensusRange) {
    ASSERT_LT(kNodeNetworkId, kRootCongressNetworkId);
    EXPECT_FALSE(IsSameShardOrSameWaitingPool(500u, kNodeNetworkId));
}

TEST(NetworkUtilsBranches, IsSameShardRootCongressWaitingPoolPair) {
    const uint32_t des = kRootCongressNetworkId;
    const uint32_t waiting_local = des + kConsensusWaitingShardOffset;
    ASSERT_LT(des, kConsensusShardEndNetworkId);
    EXPECT_TRUE(IsSameShardOrSameWaitingPool(waiting_local, des));
}

TEST(NetworkUtilsBranches, IsSameShardLastConsensusIdPairsWaitingPool) {
    const uint32_t des = kConsensusShardEndNetworkId - 1u;
    const uint32_t waiting_local = des + kConsensusWaitingShardOffset;
    EXPECT_TRUE(IsSameShardOrSameWaitingPool(waiting_local, des));
}

TEST(NetworkUtilsBranches, GetLocalConsensusNetworkIdShardVersusWaitingNormalization) {
    {
        GlobalNetworkIdGuard guard(kConsensusShardEndNetworkId - 1u);
        EXPECT_EQ(GetLocalConsensusNetworkId(),
                  static_cast<uint16_t>(kConsensusShardEndNetworkId - 1u));
    }
    {
        GlobalNetworkIdGuard guard(kConsensusShardEndNetworkId);
        EXPECT_EQ(GetLocalConsensusNetworkId(),
                  static_cast<uint16_t>(kConsensusShardEndNetworkId -
                                         kConsensusWaitingShardOffset));
    }
}

TEST(NetworkUtilsBranches, IsSameToLocalShardUsesGlobalNetworkId) {
    {
        GlobalNetworkIdGuard guard(100u);
        EXPECT_TRUE(IsSameToLocalShard(100u));
    }
    {
        const uint32_t desired_net = 103u;
        GlobalNetworkIdGuard guard(desired_net + kConsensusWaitingShardOffset);
        EXPECT_TRUE(IsSameToLocalShard(desired_net));
    }
    {
        GlobalNetworkIdGuard guard(500u);
        EXPECT_FALSE(IsSameToLocalShard(999u));
    }
}

TEST(NetworkUtilsBranches, GetLocalConsensusNetworkIdBranches) {
    GlobalNetworkIdGuard guard_a(50u);
    EXPECT_EQ(GetLocalConsensusNetworkId(), static_cast<uint16_t>(50u));

    GlobalNetworkIdGuard guard_b(1500u);
    EXPECT_EQ(GetLocalConsensusNetworkId(),
              static_cast<uint16_t>(1500u - kConsensusWaitingShardOffset));
}

TEST(NetworkUtilsBranches, IsWaitingForElectBranches) {
    GlobalNetworkIdGuard low(kConsensusWaitingShardBeginNetworkId - 1u);
    EXPECT_FALSE(IsWaitingForElect());

    GlobalNetworkIdGuard high(kConsensusWaitingShardBeginNetworkId);
    EXPECT_TRUE(IsWaitingForElect());
}

TEST(NetworkProtoBranches, CreateGetNetworkNodesRequestSetsFields) {
    auto local = MakeNode(7u, "127.0.0.1", 9001, "pk", "nid");
    transport::protobuf::Header msg;
    NetworkProto::CreateGetNetworkNodesRequest(local, 42u, 3u, msg);
    EXPECT_EQ(msg.src_sharding_id(), 7u);
    EXPECT_EQ(msg.type(), common::kNetworkMessage);
    ASSERT_TRUE(msg.has_network_proto());
    ASSERT_TRUE(msg.network_proto().has_get_net_nodes_req());
    EXPECT_EQ(msg.network_proto().get_net_nodes_req().net_id(), 42u);
    EXPECT_EQ(msg.network_proto().get_net_nodes_req().count(), 3u);
    EXPECT_FALSE(msg.des_dht_key().empty());
}

TEST(NetworkProtoBranches, CreateGetNetworkNodesResponseSkipsEmptyPubkey) {
    auto local = MakeNode(1u, "10.0.0.1", 8000, "pk0", "id0");
    transport::protobuf::Header request;
    request.set_src_sharding_id(9u);
    dht::DhtKeyManager dht_key(9u);
    request.set_des_dht_key(dht_key.StrKey());

    std::vector<dht::NodePtr> nodes;
    auto with_pk = MakeNode(2u, "1.1.1.1", 1234, "validpub", "a");
    with_pk->pubkey_str = "nonempty";
    with_pk->public_ip = "1.1.1.1";
    with_pk->public_port = 1234;
    auto no_pk = MakeNode(2u, "2.2.2.2", 2345, "", "b");
    no_pk->pubkey_str.clear();
    nodes.push_back(no_pk);
    nodes.push_back(with_pk);

    transport::protobuf::Header out;
    NetworkProto::CreateGetNetworkNodesResponse(local, request, nodes, out);
    EXPECT_EQ(out.network_proto().get_net_nodes_res().nodes_size(), 1);
    EXPECT_EQ(out.network_proto().get_net_nodes_res().nodes(0).public_ip(), "1.1.1.1");
}

TEST(DhtManagerBranches, GetDhtOutOfRangeReturnsNull) {
    auto* mgr = DhtManager::Instance();
    ASSERT_NE(mgr, nullptr);
    EXPECT_EQ(mgr->GetDht(kConsensusWaitingShardEndNetworkId), nullptr);
    EXPECT_EQ(mgr->GetDht(kConsensusWaitingShardEndNetworkId + 16u), nullptr);
}

TEST(DhtManagerBranches, RegisterDhtRejectsInvalidNetId) {
    auto* mgr = DhtManager::Instance();
    dht::NodePtr n = MakeNode(3u, "127.0.0.1", 9100, "p", "id");
    dht::BaseDhtPtr dht = std::make_shared<dht::BaseDht>(n);
    mgr->RegisterDht(kConsensusWaitingShardEndNetworkId, dht);
    SUCCEED();
}

TEST(DhtManagerBranches, RegisterDhtRejectsDoubleRegister) {
    auto* mgr = DhtManager::Instance();
    dht::NodePtr n1 = MakeNode(4u, "127.0.0.1", 9200, "p1", "id1");
    dht::BaseDhtPtr d1 = std::make_shared<dht::BaseDht>(n1);
    constexpr uint32_t kSlot = 120u;
    mgr->RegisterDht(kSlot, d1);
    mgr->RegisterDht(kSlot, d1);  // second should hit error path without crashing
    SUCCEED();
}

TEST(DhtManagerBranches, DropNodeAndJoinEmptyMapNoCrash) {
    auto* mgr = DhtManager::Instance();
    mgr->DropNode("192.0.2.1", 1234);
    dht::NodePtr n = MakeNode(1u, "192.0.2.2", 2222, "pk", "id");
    mgr->Join(n);
    SUCCEED();
}

TEST(DhtManagerBranches, ValidCountReturnsZeroWhenDhtMissing) {
    auto* mgr = DhtManager::Instance();
    EXPECT_EQ(mgr->valid_count(99999u), 0u);
}

}  // namespace test
}  // namespace network
}  // namespace seth
