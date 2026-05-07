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

TEST(HotstuffUtilsBranches, ChainTypeConstants) {
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kInvalidChain), -1);
    EXPECT_EQ(static_cast<int32_t>(hotstuff::kLocalChain), 0);
}

TEST(HotstuffUtilsBranches, GlobalChainIdConstant) {
    EXPECT_EQ(kGlobalChainId, 3355103125llu);
}

}  // namespace test
}  // namespace consensus
}  // namespace seth
