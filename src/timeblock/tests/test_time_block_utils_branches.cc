#include <gtest/gtest.h>

#include "timeblock/time_block_utils.h"

namespace seth {
namespace timeblock {
namespace test {

TEST(TimeBlockUtilsBranches, RootErrorCodeValues) {
    EXPECT_EQ(static_cast<int>(kTimeBlockSuccess), 0);
    EXPECT_EQ(kTimeBlockTolerateSeconds, 30llu);
    EXPECT_EQ(kTimeBlockMaxOffsetSeconds, 10llu);
    EXPECT_EQ(kTimeBlockAvgCount, 6u);
    EXPECT_EQ(kCheckTimeBlockPeriodUs, 1000000llu);
    EXPECT_EQ(kCheckBftPeriodUs, 1000000llu);
}

TEST(TimeBlockUtilsBranches, RootErrorCodeFullEnum) {
    EXPECT_EQ(static_cast<int>(kTimeBlockSuccess), 0);
    EXPECT_EQ(static_cast<int>(kTimeBlockError), 1);
    EXPECT_EQ(static_cast<int>(kTimeBlockVssError), 2);
}

TEST(TimeBlockUtilsBranches, RootErrorCodesStrictlyOrdered) {
    EXPECT_LT(static_cast<int>(kTimeBlockSuccess), static_cast<int>(kTimeBlockError));
    EXPECT_LT(static_cast<int>(kTimeBlockError), static_cast<int>(kTimeBlockVssError));
}

TEST(TimeBlockUtilsBranches, TolerateVersusMaxOffset) {
    EXPECT_GE(kTimeBlockTolerateSeconds, kTimeBlockMaxOffsetSeconds);
}

TEST(TimeBlockUtilsBranches, CheckPeriodsMatchVssTimeblockConstants) {
    EXPECT_EQ(kCheckTimeBlockPeriodUs, kCheckBftPeriodUs);
    EXPECT_GT(kTimeBlockAvgCount, 0u);
}

TEST(TimeBlockUtilsBranches, TolerateWindowCoversMaxOffset) {
    EXPECT_GE(kTimeBlockTolerateSeconds, kTimeBlockMaxOffsetSeconds);
}

TEST(TimeBlockUtilsBranches, CheckPeriodsAreOneSecond) {
    EXPECT_EQ(kCheckTimeBlockPeriodUs, 1000000llu);
    EXPECT_EQ(kCheckBftPeriodUs, 1000000llu);
}

}  // namespace test
}  // namespace timeblock
}  // namespace seth
