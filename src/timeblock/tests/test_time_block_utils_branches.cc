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

}  // namespace test
}  // namespace timeblock
}  // namespace seth
