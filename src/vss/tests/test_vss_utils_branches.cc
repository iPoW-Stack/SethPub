#include <gtest/gtest.h>

#include "elect/elect_utils.h"
#include "vss/vss_utils.h"

namespace shardora {
namespace vss {
namespace test {

TEST(VssUtilsBranches, ElectItemDefaults) {
    ElectItem item;
    EXPECT_EQ(item.members, nullptr);
    EXPECT_EQ(item.member_count, 0u);
    EXPECT_EQ(item.elect_height, 0ull);
    EXPECT_FALSE(item.this_node_is_leader);
    EXPECT_EQ(item.local_index, elect::kInvalidMemberIndex);
}

TEST(VssUtilsBranches, VssConstants) {
    EXPECT_EQ(kVssRandomHash, 1);
    EXPECT_EQ(kVssRandomSplitCount, 3);
    EXPECT_EQ(kVssRandomduplicationCount, 7u);
    EXPECT_EQ(kVssTimePeriodOffsetSeconds, 3u);
    EXPECT_EQ(kHandleMessageVssTimePeriodOffsetSeconds, 1u);
}

TEST(VssUtilsBranches, VssErrorCodeEnum) {
    EXPECT_EQ(kVssSuccess, 0);
    EXPECT_EQ(kVssError, 1);
}

TEST(VssUtilsBranches, VssMessageTypeEnumValues) {
    EXPECT_EQ(kVssRandomHash, 1);
    EXPECT_EQ(kVssRandom, 2);
    EXPECT_EQ(kVssFinalRandom, 3);
    EXPECT_LT(kVssRandomHash, kVssRandom);
    EXPECT_LT(kVssRandom, kVssFinalRandom);
}

TEST(VssUtilsBranches, ElectItemConstructibleAndAssignable) {
    ElectItem a;
    ElectItem b;
    b.member_count = 3u;
    b.elect_height = 9ull;
    b.this_node_is_leader = true;
    a = b;
    EXPECT_EQ(a.member_count, 3u);
    EXPECT_EQ(a.elect_height, 9ull);
    EXPECT_TRUE(a.this_node_is_leader);
}

TEST(VssUtilsBranches, TimeoutMicrosecondsPositive) {
    EXPECT_GT(kVssCheckPeriodTimeout, 0ll);
}

TEST(VssUtilsBranches, PeriodOffsetsOrderedAndBelowTimeoutWindow) {
    EXPECT_GT(kVssTimePeriodOffsetSeconds, kHandleMessageVssTimePeriodOffsetSeconds);
    EXPECT_LT(static_cast<int64_t>(kVssTimePeriodOffsetSeconds * 1000ll),
              kVssCheckPeriodTimeout);
}

TEST(VssUtilsBranches, VssTimingAndDuplicationConstantsExactValues) {
    EXPECT_EQ(kVssRandomSplitCount, 3);
    EXPECT_EQ(kVssRandomduplicationCount, 7u);
    EXPECT_EQ(kVssCheckPeriodTimeout, 3000000ll);
}

TEST(VssUtilsBranches, ElectItemLeaderFlagCanBeToggled) {
    ElectItem item;
    EXPECT_FALSE(item.this_node_is_leader);
    item.this_node_is_leader = true;
    EXPECT_TRUE(item.this_node_is_leader);
}

}  // namespace test
}  // namespace vss
}  // namespace shardora
