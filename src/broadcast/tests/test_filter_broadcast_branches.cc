#include <gtest/gtest.h>

#include <limits>
#include <string>
#include <unordered_set>

#include "dht/dht_utils.h"
#include "dht/base_dht.h"
#include "broadcast/broadcast_utils.h"
#include "transport/transport_utils.h"
#define private public
#include "broadcast/filter_broadcast.h"
#undef private

namespace shardora {
namespace broadcast {
namespace test {

namespace {

dht::NodePtr MakeNode(const std::string& id, uint16_t port, uint64_t forced_hash) {
    auto node = std::make_shared<dht::Node>(1, "127.0.0.1", port, "pubkey", id);
    node->id_hash = forced_hash;
    return node;
}

dht::BaseDhtPtr MakeBaseDhtWithNodes(uint32_t count) {
    auto local = MakeNode("local", 9000, 100);
    auto dht_ptr = std::make_shared<dht::BaseDht>(local);
    for (uint32_t i = 0; i < count; ++i) {
        auto node = MakeNode("node_" + std::to_string(i), static_cast<uint16_t>(9100 + i), 200 + i * 10);
        EXPECT_EQ(dht_ptr->Join(node), dht::kDhtSuccess);
    }
    return dht_ptr;
}

}  // namespace

TEST(TestFilterBroadcastBranches, GetBloomfilterHandlesEmptyAndFilled) {
    FilterBroadcast filter;
    transport::protobuf::Header msg;

    auto empty = filter.GetBloomfilter(msg);
    EXPECT_TRUE(empty->empty());

    msg.mutable_broadcast()->add_bloomfilter(11);
    msg.mutable_broadcast()->add_bloomfilter(22);
    auto filled = filter.GetBloomfilter(msg);
    EXPECT_EQ(filled->size(), 2u);
    EXPECT_TRUE(filled->count(11) > 0);
    EXPECT_TRUE(filled->count(22) > 0);
}

TEST(TestFilterBroadcastBranches, SetDefaultBroadcastParamAssignsExpectedDefaults) {
    transport::protobuf::BroadcastParam brd;
    brd.set_ign_bloomfilter_hop(999);
    brd.set_hop_to_layer(999);
    brd.set_hop_limit(999);
    brd.set_layer_left(999);
    brd.set_layer_right(999);
    brd.set_neighbor_count(999);
    brd.set_overlap(0.125f);
    brd.add_bloomfilter(1);
    brd.add_bloomfilter(2);

    SetDefaultBroadcastParam(&brd);

    EXPECT_EQ(brd.ign_bloomfilter_hop(), kBroadcastIgnBloomfilter);
    EXPECT_EQ(brd.hop_to_layer(), 0);
    EXPECT_EQ(brd.hop_limit(), static_cast<int32_t>(kBroadcastHopLimit));
    EXPECT_EQ(brd.layer_left(), 0u);
    EXPECT_EQ(brd.layer_right(), common::kInvalidUint64);
    EXPECT_EQ(brd.neighbor_count(), static_cast<int32_t>(kBroadcastDefaultNeighborCount));
    EXPECT_FLOAT_EQ(brd.overlap(), 1.0f);
    EXPECT_EQ(brd.bloomfilter_size(), 0);
}

TEST(TestFilterBroadcastBranches, BroadcastUtilsConstantsAreStable) {
    EXPECT_EQ(kBroadcastDefaultNeighborCount, 13u);
    EXPECT_EQ(kBloomfilterBitSize, 256u);
    EXPECT_EQ(kBloomfilterHashCount, 3u);
    EXPECT_EQ(kBroadcastHopLimit, 16u);
    EXPECT_EQ(kBroadcastHopToLayer, 1u);
    EXPECT_EQ(kBroadcastIgnBloomfilter, 1u);
}

TEST(TestFilterBroadcastBranches, GetBloomfilterDeduplicatesEntries) {
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->add_bloomfilter(7);
    brd->add_bloomfilter(7);
    brd->add_bloomfilter(8);
    auto setv = filter.GetBloomfilter(msg);
    EXPECT_EQ(setv->size(), 2u);
    EXPECT_TRUE(setv->count(7) > 0);
    EXPECT_TRUE(setv->count(8) > 0);
}

TEST(TestFilterBroadcastBranches, BinarySearchCoversEdges) {
    FilterBroadcast filter;
    dht::Dht nodes;
    nodes.push_back(MakeNode("a", 9201, 100));
    nodes.push_back(MakeNode("b", 9202, 200));
    nodes.push_back(MakeNode("c", 9203, 300));

    EXPECT_EQ(filter.BinarySearch(nodes, 50), 0u);
    EXPECT_EQ(filter.BinarySearch(nodes, 200), 1u);
    EXPECT_EQ(filter.BinarySearch(nodes, 999), 2u);
}

TEST(TestFilterBroadcastBranches, BinarySearchAdjustsToPreviousIndex) {
    FilterBroadcast filter;
    dht::Dht nodes;
    nodes.push_back(MakeNode("a", 9201, 100));
    nodes.push_back(MakeNode("b", 9202, 200));
    nodes.push_back(MakeNode("c", 9203, 300));
    // 150 lands between 100 and 200, should take "mid > 0 then --mid" path.
    EXPECT_EQ(filter.BinarySearch(nodes, 150), 0u);
}

TEST(TestFilterBroadcastBranches, BinarySearchExactMatchUsesEqualityBranch) {
    FilterBroadcast filter;
    dht::Dht nodes;
    nodes.push_back(MakeNode("a", 9201, 100));
    nodes.push_back(MakeNode("b", 9202, 200));
    nodes.push_back(MakeNode("c", 9203, 300));
    EXPECT_EQ(filter.BinarySearch(nodes, 200), 1u);
}

TEST(TestFilterBroadcastBranches, BinarySearchSingleSortedNodeCoversOneElementLoop) {
    FilterBroadcast filter;
    dht::Dht nodes;
    nodes.push_back(MakeNode("only", 9210, 500u));
    EXPECT_EQ(filter.BinarySearch(nodes, 50u), 0u);
    EXPECT_EQ(filter.BinarySearch(nodes, 500u), 0u);
    EXPECT_EQ(filter.BinarySearch(nodes, 900u), 0u);
}

TEST(TestFilterBroadcastBranches, LayerRangeHelpersHandleSentinelAndOverlap) {
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    msg.set_hop_count(2);
    msg.mutable_broadcast()->set_overlap(0.5f);

    EXPECT_EQ(filter.GetLayerLeft(0, msg), 0u);
    EXPECT_LT(filter.GetLayerLeft(1000, msg), 1000u);

    EXPECT_EQ(filter.GetLayerRight(common::kInvalidUint64, msg), common::kInvalidUint64);
    EXPECT_GT(filter.GetLayerRight(1000, msg), 1000u);
}

TEST(TestFilterBroadcastBranches, GetLayerNodesHandlesNullReadonlyDht) {
    auto local = MakeNode("local", 9300, 123);
    dht::BaseDhtPtr dht_ptr = std::make_shared<dht::BaseDht>(local);
    FilterBroadcast filter;
    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    transport::protobuf::Header msg;
    msg.mutable_broadcast()->set_layer_left(0);
    msg.mutable_broadcast()->set_layer_right(std::numeric_limits<uint64_t>::max());

    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_TRUE(nodes.empty());
}

TEST(TestFilterBroadcastBranches, GetLayerNodesRespectsNeighborCountAndBloom) {
    auto dht_ptr = MakeBaseDhtWithNodes(16);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    brd->set_neighbor_count(3);
    brd->set_ign_bloomfilter_hop(0);
    brd->set_overlap(1.0f);
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_LE(nodes.size(), 3u);
    EXPECT_GT(brd->bloomfilter_size(), 0);
}

TEST(TestFilterBroadcastBranches, GetLayerNodesCapsBloomFilterSerializationAt64) {
    auto dht_ptr = MakeBaseDhtWithNodes(80);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    brd->set_neighbor_count(80);
    brd->set_ign_bloomfilter_hop(0);
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_FALSE(nodes.empty());
    EXPECT_LE(brd->bloomfilter_size(), 64);
}

TEST(TestFilterBroadcastBranches, GetLayerNodesSkipsPrefilteredAndNoIgnInsert) {
    auto dht_ptr = MakeBaseDhtWithNodes(10);
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_FALSE(readonly->empty());

    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    brd->set_neighbor_count(6);
    brd->set_ign_bloomfilter_hop(100);  // keep line-148 false
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    // Pre-filter several candidates to exercise continue path.
    bloom->insert((*readonly)[0]->id_hash);
    bloom->insert((*readonly)[1]->id_hash);
    bloom->insert((*readonly)[2]->id_hash);
    auto before_size = bloom->size();
    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_LE(nodes.size(), 6u);
    EXPECT_EQ(bloom->size(), before_size + 1);  // only local node is inserted
}

TEST(TestFilterBroadcastBranches, GetLayerNodesReturnsEmptyOnInvalidRange) {
    auto dht_ptr = MakeBaseDhtWithNodes(8);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    // Build an inverted range so left > right after BinarySearch.
    brd->set_layer_left(std::numeric_limits<uint64_t>::max());
    brd->set_layer_right(0);
    brd->set_neighbor_count(5);
    brd->set_ign_bloomfilter_hop(0);
    msg.set_hop_count(0);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_TRUE(nodes.empty());
}

TEST(TestFilterBroadcastBranches, GetRandomFilterNodesCoversBloomAndLimit) {
    auto dht_ptr = MakeBaseDhtWithNodes(12);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_neighbor_count(4);
    brd->set_ign_bloomfilter_hop(0);
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_FALSE(readonly->empty());
    // Pre-filter at least one node to exercise continue branch.
    bloom->insert((*readonly)[0]->id_hash);

    auto nodes = filter.GetRandomFilterNodes(dht_ptr, bloom, msg);
    EXPECT_LE(nodes.size(), 4u);
    EXPECT_GT(msg.broadcast().bloomfilter_size(), 0);
}

TEST(TestFilterBroadcastBranches, GetRandomFilterNodesWithoutBloomInsertionBranch) {
    auto dht_ptr = MakeBaseDhtWithNodes(10);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_neighbor_count(5);
    brd->set_ign_bloomfilter_hop(10);  // now_hop=1 will not insert selected nodes
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    auto nodes = filter.GetRandomFilterNodes(dht_ptr, bloom, msg);
    EXPECT_LE(nodes.size(), 5u);
    EXPECT_GE(msg.broadcast().bloomfilter_size(), 1);  // at least local node hash
}

TEST(TestFilterBroadcastBranches, GetRandomFilterNodesCapsSerializedBloomAt64) {
    auto dht_ptr = MakeBaseDhtWithNodes(20);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_neighbor_count(10);
    brd->set_ign_bloomfilter_hop(0);
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    for (uint64_t i = 0; i < 128; ++i) {
        bloom->insert(100000 + i);
    }

    auto nodes = filter.GetRandomFilterNodes(dht_ptr, bloom, msg);
    EXPECT_LE(nodes.size(), 10u);
    EXPECT_LE(msg.broadcast().bloomfilter_size(), 64);
}

TEST(TestFilterBroadcastBranches, GetRandomFilterNodesAllPrefilteredReturnsEmpty) {
    auto dht_ptr = MakeBaseDhtWithNodes(10);
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_FALSE(readonly->empty());

    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_neighbor_count(10);
    brd->set_ign_bloomfilter_hop(0);
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    for (const auto& node : *readonly) {
        bloom->insert(node->id_hash);
    }

    auto nodes = filter.GetRandomFilterNodes(dht_ptr, bloom, msg);
    EXPECT_TRUE(nodes.empty());
    EXPECT_GE(msg.broadcast().bloomfilter_size(), 1);
}

TEST(TestFilterBroadcastBranches, LayerRangeHelpersWithoutOverlapKeepBounds) {
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    msg.set_hop_count(3);
    // has_overlap() is false, should not adjust.
    EXPECT_EQ(filter.GetLayerLeft(1234, msg), 1234u);
    EXPECT_EQ(filter.GetLayerRight(5678, msg), 5678u);

    // overlap set to 0 triggers epsilon branch (no adjustment) even when present.
    msg.mutable_broadcast()->set_overlap(0.0f);
    EXPECT_EQ(filter.GetLayerLeft(2222, msg), 2222u);
    EXPECT_EQ(filter.GetLayerRight(3333, msg), 3333u);
}

TEST(TestFilterBroadcastBranches, BroadcastingNormalPathIncrementsHop) {
    auto dht_ptr = MakeBaseDhtWithNodes(10);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    brd->set_neighbor_count(2);
    brd->set_ign_bloomfilter_hop(0);
    brd->set_hop_limit(100);
    msg_ptr->header.set_hop_count(0);

    filter.Broadcasting(dht_ptr, msg_ptr);
    EXPECT_EQ(msg_ptr->header.hop_count(), 1u);
}

TEST(TestFilterBroadcastBranches, BroadcastingWithoutHopLimitStillRuns) {
    auto dht_ptr = MakeBaseDhtWithNodes(6);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    brd->set_neighbor_count(2);
    brd->set_ign_bloomfilter_hop(0);
    // no hop_limit field set: exercise has_hop_limit()==false path
    msg_ptr->header.set_hop_count(0);

    filter.Broadcasting(dht_ptr, msg_ptr);
    EXPECT_EQ(msg_ptr->header.hop_count(), 1u);
}

TEST(TestFilterBroadcastBranches, SendWithEmptyNodesIsNoop) {
    auto dht_ptr = MakeBaseDhtWithNodes(4);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    std::vector<dht::NodePtr> nodes;
    filter.Send(dht_ptr, msg_ptr, nodes);
    SUCCEED();
}

TEST(TestFilterBroadcastBranches, SendWithOneNodeExecutesLoopBody) {
    auto dht_ptr = MakeBaseDhtWithNodes(4);
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_FALSE(readonly->empty());
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    std::vector<dht::NodePtr> nodes = {(*readonly)[0]};
    filter.Send(dht_ptr, msg_ptr, nodes);
    SUCCEED();
}

TEST(TestFilterBroadcastBranches, LayerSendCoversOneAndMultipleNodeBranches) {
    auto dht_ptr = MakeBaseDhtWithNodes(6);
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_GE(readonly->size(), 4u);

    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_overlap(1.0f);
    brd->set_layer_left(10);
    brd->set_layer_right(1000);
    msg_ptr->header.set_hop_count(1);

    // i == 0 and nodes.size() == 1 branch
    std::vector<dht::NodePtr> one = {(*readonly)[0]};
    filter.LayerSend(dht_ptr, msg_ptr, one);
    EXPECT_EQ(msg_ptr->header.broadcast().layer_left(), 0u);
    EXPECT_EQ(msg_ptr->header.broadcast().layer_right(), 2000u);

    // i == 0, middle, and last branches
    brd->set_layer_left(10);
    brd->set_layer_right(1000);
    std::vector<dht::NodePtr> multi = {(*readonly)[0], (*readonly)[1], (*readonly)[2]};
    filter.LayerSend(dht_ptr, msg_ptr, multi);
    EXPECT_GE(msg_ptr->header.broadcast().layer_right(), msg_ptr->header.broadcast().layer_left());
}

TEST(TestFilterBroadcastBranches, LayerSendWithTwoNodesCoversLastBranch) {
    auto dht_ptr = MakeBaseDhtWithNodes(4);
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_GE(readonly->size(), 2u);

    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_overlap(1.0f);
    brd->set_layer_left(10);
    brd->set_layer_right(500);
    msg_ptr->header.set_hop_count(1);

    std::vector<dht::NodePtr> two = {(*readonly)[0], (*readonly)[1]};
    filter.LayerSend(dht_ptr, msg_ptr, two);
    EXPECT_GE(msg_ptr->header.broadcast().layer_right(), msg_ptr->header.broadcast().layer_left());
}

TEST(TestFilterBroadcastBranches, GetLayerNodesAllPrefilteredReturnsEmpty) {
    auto dht_ptr = MakeBaseDhtWithNodes(8);
    auto readonly = dht_ptr->readonly_hash_sort_dht();
    ASSERT_TRUE(readonly != nullptr);
    ASSERT_FALSE(readonly->empty());

    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    brd->set_neighbor_count(8);
    brd->set_ign_bloomfilter_hop(0);
    msg.set_hop_count(1);

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    for (const auto& node : *readonly) {
        bloom->insert(node->id_hash);
    }

    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_TRUE(nodes.empty());
    EXPECT_GE(brd->bloomfilter_size(), 1);
}

TEST(TestFilterBroadcastBranches, GetLayerNodesAppliesOverlapAdjustment) {
    auto dht_ptr = MakeBaseDhtWithNodes(20);
    FilterBroadcast filter;
    transport::protobuf::Header msg;
    auto* brd = msg.mutable_broadcast();
    brd->set_layer_left(250);
    brd->set_layer_right(260);
    brd->set_neighbor_count(5);
    brd->set_ign_bloomfilter_hop(0);
    brd->set_overlap(0.5f);
    msg.set_hop_count(2);  // pow(0.5,2)=0.25, triggers adjust branches

    auto bloom = std::make_shared<std::unordered_set<uint64_t>>();
    auto nodes = filter.GetlayerNodes(dht_ptr, bloom, msg);
    EXPECT_LE(nodes.size(), 5u);
    EXPECT_GE(msg.broadcast().bloomfilter_size(), 1);
}

TEST(TestFilterBroadcastBranches, LayerSendWithEmptyNodesIsNoop) {
    auto dht_ptr = MakeBaseDhtWithNodes(3);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_layer_left(10);
    brd->set_layer_right(200);
    std::vector<dht::NodePtr> none;
    filter.LayerSend(dht_ptr, msg_ptr, none);
    EXPECT_EQ(msg_ptr->header.broadcast().layer_left(), 10u);
    EXPECT_EQ(msg_ptr->header.broadcast().layer_right(), 200u);
}

TEST(TestFilterBroadcastBranches, BroadcastingReturnsWhenHopLimitEqualsCurrentHop) {
    auto dht_ptr = MakeBaseDhtWithNodes(6);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_hop_limit(2);
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    msg_ptr->header.set_hop_count(2);  // equal boundary
    filter.Broadcasting(dht_ptr, msg_ptr);
    EXPECT_EQ(msg_ptr->header.hop_count(), 2u);
}

TEST(TestFilterBroadcastBranches, BroadcastingReturnsEarlyOnHopLimit) {
    auto dht_ptr = MakeBaseDhtWithNodes(8);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_hop_limit(1);
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    msg_ptr->header.set_hop_count(1);

    filter.Broadcasting(dht_ptr, msg_ptr);
    EXPECT_EQ(msg_ptr->header.hop_count(), 1u);
}

TEST(TestFilterBroadcastBranches, BroadcastingReturnsEarlyOnGlobalHopLimit) {
    auto dht_ptr = MakeBaseDhtWithNodes(8);
    FilterBroadcast filter;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    auto* brd = msg_ptr->header.mutable_broadcast();
    brd->set_hop_limit(1000);
    brd->set_layer_left(0);
    brd->set_layer_right(std::numeric_limits<uint64_t>::max());
    msg_ptr->header.set_hop_count(kBroadcastHopLimit);

    filter.Broadcasting(dht_ptr, msg_ptr);
    EXPECT_EQ(msg_ptr->header.hop_count(), kBroadcastHopLimit);
}

}  // namespace test
}  // namespace broadcast
}  // namespace shardora
