#include <gtest/gtest.h>

#include "elect/elect_utils.h"
#include "vss/vss_utils.h"

namespace seth {
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

}  // namespace test
}  // namespace vss
}  // namespace seth
