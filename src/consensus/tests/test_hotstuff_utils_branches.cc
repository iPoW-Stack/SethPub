#include <gtest/gtest.h>

#include "consensus/hotstuff/types.h"
#include "consensus/hotstuff/utils.h"
#include "protos/block.pb.h"

namespace seth {
namespace consensus {
namespace test {

using hotstuff::BlockViewKey;
using hotstuff::kGlobalChainId;

namespace {

struct FakeProtoSerializeFail {
    size_t ByteSizeLong() const { return 7; }
    bool IsInitialized() const { return true; }
    bool SerializePartialToCodedStream(google::protobuf::io::CodedOutputStream*) const {
        return false;
    }
};

struct FakeProtoUninitializedEmpty {
    size_t ByteSizeLong() const { return 0; }
    bool IsInitialized() const { return false; }
    bool SerializePartialToCodedStream(google::protobuf::io::CodedOutputStream*) const {
        return true;
    }
};

struct FakeProtoInitializedEmpty {
    size_t ByteSizeLong() const { return 0; }
    bool IsInitialized() const { return true; }
    bool SerializePartialToCodedStream(google::protobuf::io::CodedOutputStream*) const {
        return true;
    }
};

view_block::protobuf::ViewBlockItem MakeMinimalViewBlock(
        uint32_t network_id,
        uint32_t pool_index,
        uint32_t leader_idx,
        uint64_t view,
        uint64_t chain_id,
        uint64_t height,
        const std::string& parent_hash) {
    view_block::protobuf::ViewBlockItem vb;
    vb.set_parent_hash(parent_hash);
    auto* qc = vb.mutable_qc();
    qc->set_network_id(network_id);
    qc->set_pool_index(pool_index);
    qc->set_leader_idx(leader_idx);
    qc->set_view(view);
    auto* bi = vb.mutable_block_info();
    bi->set_chain_id(chain_id);
    bi->set_height(height);
    bi->set_timestamp(1000);
    bi->set_consistency_random(1);
    bi->set_timeblock_height(1);
    return vb;
}

}  // namespace

TEST(HotstuffUtilsBranches, BlockViewKeyEqualityAndOrder) {
    BlockViewKey a(3u, 9u, 100ull);
    BlockViewKey b(3u, 9u, 100ull);
    BlockViewKey c(3u, 9u, 101ull);
    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a == c);
    EXPECT_TRUE(a < c);
    EXPECT_FALSE(c < a);
}

TEST(HotstuffUtilsBranches, BlockViewKeyLexicographicTieBreaks) {
    BlockViewKey by_net(1u, 9u, 100ull);
    BlockViewKey bigger_net(2u, 1u, 1ull);
    EXPECT_TRUE(by_net < bigger_net);

    BlockViewKey by_pool(5u, 1u, 100ull);
    BlockViewKey bigger_pool(5u, 2u, 100ull);
    EXPECT_TRUE(by_pool < bigger_pool);

    BlockViewKey by_view(5u, 5u, 10ull);
    BlockViewKey bigger_view(5u, 5u, 11ull);
    EXPECT_TRUE(by_view < bigger_view);
}

TEST(HotstuffUtilsBranches, BlockViewKeyComparesFirstDifferingFieldOnly) {
    const BlockViewKey base(3u, 4u, 5ull);
    EXPECT_TRUE(base < BlockViewKey(4u, 0u, 0ull));
    EXPECT_TRUE(base < BlockViewKey(3u, 5u, 0ull));
    EXPECT_TRUE(base < BlockViewKey(3u, 4u, 6ull));
}

TEST(HotstuffUtilsBranches, BlockViewKeyHashStableForEqualKeys) {
    BlockViewKey k1(5u, 7u, 42ull);
    BlockViewKey k2(5u, 7u, 42ull);
    BlockViewKey k3(5u, 8u, 42ull);
    std::hash<BlockViewKey> h;
    EXPECT_EQ(h(k1), h(k2));
    EXPECT_NE(h(k1), h(k3));
}

TEST(HotstuffUtilsBranches, BlockViewKeyHashChangesAcrossDifferentFields) {
    std::hash<BlockViewKey> h;
    const BlockViewKey base(5u, 7u, 42ull);
    EXPECT_NE(h(base), h(BlockViewKey(6u, 7u, 42ull)));
    EXPECT_NE(h(base), h(BlockViewKey(5u, 7u, 43ull)));
}

TEST(HotstuffUtilsBranches, SerializeDeterministicIsRepeatable) {
    block::protobuf::Block msg;
    msg.set_height(12345u);
    msg.set_chain_id(99ull);

    std::string s1 = SerializeDeterministic(msg);
    std::string s2 = SerializeDeterministic(msg);

    ASSERT_FALSE(s1.empty());
    EXPECT_EQ(s1, s2);
}

TEST(HotstuffUtilsBranches, SerializeDeterministicDefaultEmptyBlock) {
    block::protobuf::Block empty;
    std::string s = SerializeDeterministic(empty);
    (void)s;
}

TEST(HotstuffUtilsBranches, SerializeDeterministicDiffersWhenFieldsChange) {
    block::protobuf::Block a;
    a.set_height(10u);
    a.set_chain_id(100ull);
    block::protobuf::Block b;
    b.set_height(11u);
    b.set_chain_id(100ull);
    EXPECT_NE(SerializeDeterministic(a), SerializeDeterministic(b));
}

TEST(HotstuffUtilsBranches, SerializeDeterministicSensitiveToChainId) {
    block::protobuf::Block a;
    a.set_height(20u);
    a.set_chain_id(100ull);
    block::protobuf::Block b;
    b.set_height(20u);
    b.set_chain_id(101ull);
    EXPECT_NE(SerializeDeterministic(a), SerializeDeterministic(b));
}

TEST(HotstuffUtilsBranches, SerializeDeterministicReturnsEmptyOnSerializeFailure) {
    const FakeProtoSerializeFail msg;
    EXPECT_TRUE(SerializeDeterministic(msg).empty());
}

TEST(HotstuffUtilsBranches, SerializeDeterministicHandlesUninitializedEmptyMessage) {
    const FakeProtoUninitializedEmpty msg;
    EXPECT_TRUE(SerializeDeterministic(msg).empty());
}

TEST(HotstuffUtilsBranches, SerializeDeterministicHandlesInitializedEmptyMessage) {
    const FakeProtoInitializedEmpty msg;
    EXPECT_TRUE(SerializeDeterministic(msg).empty());
}

TEST(HotstuffUtilsBranches, ChainTypeConstants) {
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kInvalidChain), -1);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kLocalChain), 0);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kCrossRootChian), 1);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kCrossShardingChain), 2);
}

TEST(HotstuffUtilsBranches, GlobalChainIdConstant) {
    EXPECT_EQ(kGlobalChainId, 3355103125llu);
}

TEST(HotstuffUtilsBranches, StatusEnumOrderedDistinct) {
    EXPECT_EQ(hotstuff::kSuccess, 0);
    EXPECT_EQ(hotstuff::kError, 1);
    EXPECT_EQ(hotstuff::kNotFound, 2);
    EXPECT_EQ(hotstuff::kInvalidArgument, 3);
    EXPECT_EQ(hotstuff::kBlsVerifyWaiting, 4);
    EXPECT_EQ(hotstuff::kBlsVerifyFailed, 5);
    EXPECT_EQ(hotstuff::kAcceptorTxsEmpty, 6);
    EXPECT_EQ(hotstuff::kAcceptorBlockInvalid, 7);
    EXPECT_EQ(hotstuff::kOldView, 8);
    EXPECT_EQ(hotstuff::kElectItemNotFound, 9);
    EXPECT_EQ(hotstuff::kWrapperTxsEmpty, 10);
    EXPECT_EQ(hotstuff::kBlsHandled, 11);
    EXPECT_EQ(hotstuff::kTxRepeated, 12);
    EXPECT_EQ(hotstuff::kLackOfParentBlock, 13);
    EXPECT_EQ(hotstuff::kNotExpectHash, 14);
    EXPECT_EQ(hotstuff::kInvalidOpposedCount, 15);
    EXPECT_EQ(hotstuff::kLeaderInvalid, 16);
}

TEST(HotstuffUtilsBranches, WaitingBlockTypeEnumValues) {
    EXPECT_EQ(static_cast<int>(hotstuff::kRootBlock), 0);
    EXPECT_EQ(static_cast<int>(hotstuff::kSyncBlock), 1);
    EXPECT_EQ(static_cast<int>(hotstuff::kToBlock), 2);
}

TEST(HotstuffUtilsBranches, ViewDurationAndOrphanTimeoutConstants) {
    EXPECT_GT(hotstuff::ViewDurationSampleSize, 0u);
    EXPECT_GT(hotstuff::ViewDurationMaxTimeoutMs, hotstuff::ViewDurationStartTimeoutMs);
    EXPECT_GT(hotstuff::ViewDurationMultiplier, 1.0);
    EXPECT_GT(hotstuff::ORPHAN_BLOCK_TIMEOUT_US, 0ull);
}

TEST(HotstuffUtilsBranches, GetBlockHashStableForSameViewBlock) {
    auto vb = MakeMinimalViewBlock(
        3u, 1u, 2u, 10ull, kGlobalChainId, 100ull, "parent_a");
    const std::string h1 = hotstuff::GetBlockHash(vb);
    const std::string h2 = hotstuff::GetBlockHash(vb);
    EXPECT_FALSE(h1.empty());
    EXPECT_EQ(h1, h2);
}

TEST(HotstuffUtilsBranches, GetBlockHashChangesWhenParentHashChanges) {
    auto a = MakeMinimalViewBlock(
        3u, 1u, 2u, 10ull, kGlobalChainId, 100ull, "parent_a");
    auto b = a;
    b.set_parent_hash("parent_b");
    EXPECT_NE(hotstuff::GetBlockHash(a), hotstuff::GetBlockHash(b));
}

TEST(HotstuffUtilsBranches, GetBlockHashChangesWhenQcOrBlockInfoChanges) {
    auto base = MakeMinimalViewBlock(
        7u, 4u, 1u, 22ull, kGlobalChainId, 555ull, "p");

    auto change_view = base;
    change_view.mutable_qc()->set_view(base.qc().view() + 1);
    EXPECT_NE(hotstuff::GetBlockHash(base), hotstuff::GetBlockHash(change_view));

    auto change_height = base;
    change_height.mutable_block_info()->set_height(base.block_info().height() + 1);
    EXPECT_NE(hotstuff::GetBlockHash(base), hotstuff::GetBlockHash(change_height));
}

TEST(HotstuffUtilsBranches, GetBlockHashChangesWhenQcRoutingFieldsChange) {
    auto base = MakeMinimalViewBlock(
        9u, 2u, 3u, 40ull, kGlobalChainId, 888ull, "parent_x");

    auto change_net = base;
    change_net.mutable_qc()->set_network_id(base.qc().network_id() + 1);
    EXPECT_NE(hotstuff::GetBlockHash(base), hotstuff::GetBlockHash(change_net));

    auto change_pool = base;
    change_pool.mutable_qc()->set_pool_index(base.qc().pool_index() + 1);
    EXPECT_NE(hotstuff::GetBlockHash(base), hotstuff::GetBlockHash(change_pool));

    auto change_leader = base;
    change_leader.mutable_qc()->set_leader_idx(base.qc().leader_idx() + 1);
    EXPECT_NE(hotstuff::GetBlockHash(base), hotstuff::GetBlockHash(change_leader));
}

}  // namespace test
}  // namespace consensus
}  // namespace seth
