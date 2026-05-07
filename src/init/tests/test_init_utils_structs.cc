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

TEST(InitUtilsStructs, RotatitionVersionInfoHandlesInserts) {
    RotatitionVersionInfo v;
    v.handled_set.insert(11u);
    v.handled_set.insert(22u);
    v.count_map[100u] = 3u;
    EXPECT_EQ(v.handled_set.size(), 2u);
    EXPECT_EQ(v.count_map[100u], 3u);
}

TEST(InitUtilsStructs, LeaderRotationInfoContainersCanBeMutated) {
    LeaderRotationInfo info;
    info.invalid_leaders.insert(7u);
    RotatitionLeaders leaders;
    leaders.rotation_leaders.push_back(2u);
    info.rotations.push_back(leaders);
    EXPECT_EQ(info.invalid_leaders.size(), 1u);
    ASSERT_EQ(info.rotations.size(), 1u);
    EXPECT_EQ(info.rotations[0].rotation_leaders.size(), 1u);
}

TEST(InitUtilsStructs, GenisisNodeInfoSupportsFieldAssignment) {
    GenisisNodeInfo node;
    node.prikey = "pri";
    node.pubkey = "pub";
    node.id = "id";
    node.nonce = 42u;
    EXPECT_EQ(node.prikey, "pri");
    EXPECT_EQ(node.pubkey, "pub");
    EXPECT_EQ(node.id, "id");
    EXPECT_EQ(node.nonce, 42u);
}

TEST(InitUtilsStructs, RotatitionLeadersNestedVersionCounters) {
    RotatitionLeaders leaders;
    RotatitionVersionInfo info;
    info.handled_set.insert(5u);
    info.count_map[5u] = 2u;
    leaders.version_with_count[9u] = info;

    ASSERT_EQ(leaders.version_with_count.size(), 1u);
    ASSERT_EQ(leaders.version_with_count.count(9u), 1u);
    EXPECT_EQ(leaders.version_with_count[9u].handled_set.count(5u), 1u);
    EXPECT_EQ(leaders.version_with_count[9u].count_map[5u], 2u);
}

TEST(InitUtilsStructs, RotatitionLeadersHandlesMultipleVersionEntries) {
    RotatitionLeaders leaders;
    RotatitionVersionInfo v1;
    RotatitionVersionInfo v2;
    v1.count_map[1u] = 10u;
    v2.count_map[2u] = 20u;
    leaders.version_with_count[100u] = v1;
    leaders.version_with_count[200u] = v2;

    EXPECT_EQ(leaders.version_with_count.size(), 2u);
    EXPECT_EQ(leaders.version_with_count[100u].count_map[1u], 10u);
    EXPECT_EQ(leaders.version_with_count[200u].count_map[2u], 20u);
}

TEST(InitUtilsStructs, GenisisNodeInfoVectorFieldsAcceptPushBack) {
    GenisisNodeInfo node;
    node.polynomial.push_back(libff::alt_bn128_Fr::zero());
    node.verification.push_back(libff::alt_bn128_G2::zero());
    EXPECT_EQ(node.polynomial.size(), 1u);
    EXPECT_EQ(node.verification.size(), 1u);
}

TEST(InitUtilsStructs, GenisisNodeInfoPtrAliasHoldsSharedInstance) {
    GenisisNodeInfoPtr node = std::make_shared<GenisisNodeInfo>();
    ASSERT_NE(node, nullptr);
    node->nonce = 9u;
    EXPECT_EQ(node->nonce, 9u);
}

}  // namespace test
}  // namespace init
}  // namespace seth
