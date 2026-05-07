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

TEST(InitUtilsStructs, InitErrorCodeEnum) {
    EXPECT_EQ(kInitSuccess, 0);
    EXPECT_EQ(kInitError, 1);
    EXPECT_EQ(kInitWaitingForPrivateKey, 2);
}

TEST(InitUtilsStructs, RotatitionVersionInfoEmptyContainers) {
    RotatitionVersionInfo v;
    EXPECT_TRUE(v.handled_set.empty());
    EXPECT_TRUE(v.count_map.empty());
}

TEST(InitUtilsStructs, RotatitionLeadersMemberContainersInitiallyEmpty) {
    RotatitionLeaders r;
    EXPECT_TRUE(r.rotation_leaders.empty());
    EXPECT_TRUE(r.version_with_count.empty());
}

}  // namespace test
}  // namespace init
}  // namespace seth
