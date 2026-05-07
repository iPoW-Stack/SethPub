#include <gtest/gtest.h>

#include "init/init_utils.h"

namespace seth {
namespace init {
namespace test {

TEST(InitUtilsStructs, RotatitionLeadersDefaults) {
    RotatitionLeaders r;
    EXPECT_EQ(r.version, -1);
    EXPECT_EQ(r.invalid_pool_count, 0u);
    EXPECT_EQ(r.now_leader_idx, 0u);
    EXPECT_TRUE(r.rotation_leaders.empty());
    EXPECT_TRUE(r.version_with_count.empty());
}

TEST(InitUtilsStructs, LeaderRotationInfoDefaults) {
    LeaderRotationInfo info;
    EXPECT_EQ(info.elect_height, 0ull);
    EXPECT_EQ(info.members, nullptr);
    EXPECT_FALSE(info.rotation_used[0]);
}

}  // namespace test
}  // namespace init
}  // namespace seth
