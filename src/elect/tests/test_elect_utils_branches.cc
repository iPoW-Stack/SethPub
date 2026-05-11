#include <gtest/gtest.h>

#include <string>

#include "common/limit_heap.h"
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

TEST(ElectUtilsBranches, GetElectHeartbeatHashSensitiveToIp) {
    const std::string a = GetElectHeartbeatHash("198.51.100.1", 9000u, 1u, 0ull);
    const std::string b = GetElectHeartbeatHash("198.51.100.2", 9000u, 1u, 0ull);
    EXPECT_NE(a, b);
}

TEST(ElectUtilsBranches, GetElectHeartbeatHashSensitiveToPort) {
    const std::string a = GetElectHeartbeatHash("192.0.2.1", 8000u, 2u, 0ull);
    const std::string b = GetElectHeartbeatHash("192.0.2.1", 8001u, 2u, 0ull);
    EXPECT_NE(a, b);
}

TEST(ElectUtilsBranches, GetElectHeartbeatHashSensitiveToNetId) {
    const std::string a = GetElectHeartbeatHash("203.0.113.5", 9000u, 7u, 100ull);
    const std::string b = GetElectHeartbeatHash("203.0.113.5", 9000u, 8u, 100ull);
    EXPECT_NE(a, b);
}

TEST(ElectUtilsBranches, MinHeapUniqueValSensitiveToBothFields) {
    HeapItem base{11u, 22u};
    HeapItem diff_index{12u, 22u};
    HeapItem diff_succ{11u, 23u};
    const uint64_t h_base = common::MinHeapUniqueVal(base);
    EXPECT_NE(h_base, common::MinHeapUniqueVal(diff_index));
    EXPECT_NE(h_base, common::MinHeapUniqueVal(diff_succ));
}

TEST(ElectUtilsBranches, GetElectHeartbeatHashHandlesEmptyIpInput) {
    const std::string h1 = GetElectHeartbeatHash("", 0u, 0u, 0ull);
    const std::string h2 = GetElectHeartbeatHash("", 0u, 0u, 1ull);
    EXPECT_EQ(h1.size(), 32u);
    EXPECT_EQ(h2.size(), 32u);
    EXPECT_NE(h1, h2);
}

TEST(ElectUtilsBranches, HeapItemOrderingDependsOnlyOnSuccCount) {
    HeapItem lhs{1u, 100u};
    HeapItem rhs{999u, 101u};
    EXPECT_TRUE(lhs < rhs);
    rhs.succ_count = lhs.succ_count;
    EXPECT_FALSE(lhs < rhs);
}

}  // namespace test
}  // namespace elect
}  // namespace seth
