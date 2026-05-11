#include <gtest/gtest.h>

#include <string>

#include "elect/elect_utils.h"

namespace seth {
namespace elect {
namespace test {

TEST(ElectUtilsBranches, HeapItemLessComparesSuccCount) {
    HeapItem a{5u, 3u};
    HeapItem b{5u, 7u};
    EXPECT_TRUE(a < b);
    EXPECT_FALSE(b < a);
    HeapItem c{9u, 3u};
    EXPECT_FALSE(a < c);
    EXPECT_FALSE(c < a);
}

TEST(ElectUtilsBranches, HeapItemSameSuccCountIsNotLess) {
    HeapItem x{1u, 10u};
    HeapItem y{2u, 10u};
    EXPECT_FALSE(x < y);
    EXPECT_FALSE(y < x);
}

TEST(ElectUtilsBranches, MinHeapUniqueValCombinesIndexAndSucc) {
    HeapItem item{0xABCDEF01u, 0x23456789u};
    uint64_t u = common::MinHeapUniqueVal(item);
    uint64_t expected = (static_cast<uint64_t>(item.index) << 32u) | static_cast<uint64_t>(item.succ_count);
    EXPECT_EQ(u, expected);
}

TEST(ElectUtilsBranches, GetElectHeartbeatHashDeterministicAndSensitive) {
    const std::string h1 =
        GetElectHeartbeatHash("203.0.113.1", 9001u, 42u, 1000ull);
    const std::string h2 =
        GetElectHeartbeatHash("203.0.113.1", 9001u, 42u, 1000ull);
    const std::string h3 =
        GetElectHeartbeatHash("203.0.113.1", 9001u, 42u, 1001ull);

    EXPECT_EQ(h1, h2);
    EXPECT_FALSE(h1.empty());
    EXPECT_NE(h1, h3);
    EXPECT_EQ(h1.size(), 32u);  // keccak256 binary digest length used by Hash::keccak256 return
}

}  // namespace test
}  // namespace elect
}  // namespace seth
