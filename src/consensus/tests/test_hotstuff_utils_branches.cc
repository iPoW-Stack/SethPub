#include <gtest/gtest.h>

#include "consensus/hotstuff/utils.h"
#include "protos/block.pb.h"

namespace seth {
namespace consensus {
namespace test {

using hotstuff::BlockViewKey;
using hotstuff::kGlobalChainId;

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

TEST(HotstuffUtilsBranches, ChainTypeConstants) {
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kInvalidChain), -1);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kLocalChain), 0);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kCrossRootChian), 1);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kCrossShardingChain), 2);
}

TEST(HotstuffUtilsBranches, GlobalChainIdConstant) {
    EXPECT_EQ(kGlobalChainId, 3355103125llu);
}

}  // namespace test
}  // namespace consensus
}  // namespace seth
