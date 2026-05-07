#include <gtest/gtest.h>

#include "common/lof.h"

namespace seth {
namespace common {
namespace test {

TEST(LofPointBranches, ConstructorAllocatesCoordinates) {
    Point p(5, 2, 3);
    EXPECT_EQ(p.GetDimension(), 5);
    EXPECT_EQ(p.idx(), 2);
    EXPECT_EQ(p.member_idx(), 3);
    ASSERT_EQ(p.coordinate().size(), 5u);
}

TEST(LofPointBranches, SubscriptReadWrite) {
    Point p(3, 0, 0);
    p[0] = 1.25;
    p[1] = -2.5;
    EXPECT_DOUBLE_EQ(p[0], 1.25);
    EXPECT_DOUBLE_EQ(p[1], -2.5);
}

}  // namespace test
}  // namespace common
}  // namespace seth
