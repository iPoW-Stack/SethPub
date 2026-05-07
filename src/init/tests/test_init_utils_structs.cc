#include <gtest/gtest.h>

#include "init/init_utils.h"

namespace seth {
namespace init {
namespace test {

TEST(InitUtilsStructs, RotatitionLeadersDefaultMembers) {
    RotatitionLeaders r;
    EXPECT_EQ(r.version, -1);
    EXPECT_EQ(r.invalid_pool_count, 0u);
    EXPECT_EQ(r.now_leader_idx, 0u);
}

TEST(InitUtilsStructs, LeaderRotationInfoDefaults) {
    LeaderRotationInfo info;
    EXPECT_EQ(info.elect_height, 0u);
    for (bool used : info.rotation_used) {
        EXPECT_FALSE(used);
    }
}

}  // namespace test
}  // namespace init
}  // namespace seth
