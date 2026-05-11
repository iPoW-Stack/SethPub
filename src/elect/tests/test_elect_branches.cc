// Branch-coverage tests for elect module.
// Covers elect_utils.h functions and additional elect error code paths.

#include <gtest/gtest.h>
#include "elect/elect_utils.h"
#include "common/hash.h"

namespace seth {
namespace elect {
namespace test {

// ---- HeapItem::operator< ----

TEST(ElectUtilsExtraTest, HeapItemLessLhsSmaller) {
    HeapItem a, b;
    a.index = 0; a.succ_count = 5;
    b.index = 1; b.succ_count = 10;
    EXPECT_TRUE(a < b);
    EXPECT_FALSE(b < a);
}

TEST(ElectUtilsExtraTest, HeapItemLessEqual) {
    HeapItem a, b;
    a.index = 0; a.succ_count = 7;
    b.index = 1; b.succ_count = 7;
    EXPECT_FALSE(a < b);
    EXPECT_FALSE(b < a);
}

// ---- MinHeapUniqueVal ----

TEST(ElectUtilsExtraTest, MinHeapUniqueValPacking) {
    HeapItem h;
    h.index = 3;
    h.succ_count = 42;
    uint64_t v = common::MinHeapUniqueVal(h);
    EXPECT_EQ(3u, static_cast<uint32_t>(v >> 32));
    EXPECT_EQ(42u, static_cast<uint32_t>(v & 0xFFFFFFFF));
}

TEST(ElectUtilsExtraTest, MinHeapUniqueValZero) {
    HeapItem h;
    h.index = 0;
    h.succ_count = 0;
    EXPECT_EQ(0u, common::MinHeapUniqueVal(h));
}

// ---- GetElectHeartbeatHash ----

TEST(ElectUtilsExtraTest, HeartbeatHashDeterministic) {
    auto h1 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 12345678);
    auto h2 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 12345678);
    EXPECT_EQ(h1, h2);
}

TEST(ElectUtilsExtraTest, HeartbeatHashSensitiveToIp) {
    auto h1 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 100);
    auto h2 = GetElectHeartbeatHash("10.0.0.2", 9000, 3, 100);
    EXPECT_NE(h1, h2);
}

TEST(ElectUtilsExtraTest, HeartbeatHashSensitiveToPort) {
    auto h1 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 100);
    auto h2 = GetElectHeartbeatHash("10.0.0.1", 9001, 3, 100);
    EXPECT_NE(h1, h2);
}

TEST(ElectUtilsExtraTest, HeartbeatHashSensitiveToNetId) {
    auto h1 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 100);
    auto h2 = GetElectHeartbeatHash("10.0.0.1", 9000, 4, 100);
    EXPECT_NE(h1, h2);
}

TEST(ElectUtilsExtraTest, HeartbeatHashSensitiveToTime) {
    auto h1 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 100);
    auto h2 = GetElectHeartbeatHash("10.0.0.1", 9000, 3, 101);
    EXPECT_NE(h1, h2);
}

// ---- ElectErrorCode values ----

TEST(ElectConstantsExtraTest, ErrorCodeOrdering) {
    EXPECT_EQ(0, kElectSuccess);
    EXPECT_EQ(1, kElectError);
    EXPECT_LT(kElectSuccess, kElectError);
}

TEST(ElectConstantsExtraTest, InvalidMemberIndex) {
    EXPECT_EQ(std::numeric_limits<uint32_t>::max(), kInvalidMemberIndex);
}

// ---- Constants ----

TEST(ElectConstantsExtraTest, HopLimitGtHopToLayer) {
    EXPECT_GT(kElectHopLimit, kElectHopToLayer);
}

TEST(ElectConstantsExtraTest, BloomfilterSizes) {
    EXPECT_GT(kBloomfilterWaitingSize, kBloomfilterSize);
    EXPECT_GT(kBloomfilterWaitingHashCount, kBloomfilterHashCount);
}

TEST(ElectConstantsExtraTest, JoinAndTolerateTimings) {
    EXPECT_GT(kElectAvailableJoinTime, kElectAvailableTolerateTime);
}

}  // namespace test
}  // namespace elect
}  // namespace seth
