#include <gtest/gtest.h>

#include <string>

#include "common/hash.h"
#include "vss/random_num.h"

namespace seth {
namespace vss {
namespace test {

TEST(RandomNumBranches, RemoteSethashAndSetFinalWhenHashMatches) {
    constexpr uint64_t secret = 999888777ull;
    const uint64_t h = common::Hash::Hash64(std::to_string(secret));

    RandomNum remote(false);
    remote.Sethash("node_alpha", h);
    EXPECT_EQ(remote.GetHash(), h);

    remote.SetFinalRandomNum("node_alpha", secret);
    EXPECT_TRUE(remote.IsRandomValid());
    EXPECT_EQ(remote.GetFinalRandomNum(), secret);
}

TEST(RandomNumBranches, RemoteSetFinalWrongOwnerNoop) {
    constexpr uint64_t secret = 42ull;
    const uint64_t h = common::Hash::Hash64(std::to_string(secret));

    RandomNum remote(false);
    remote.Sethash("alice", h);
    remote.SetFinalRandomNum("bob", secret);
    EXPECT_FALSE(remote.IsRandomValid());
}

TEST(RandomNumBranches, RemoteSetFinalWrongSecretDoesNotBecomeValid) {
    constexpr uint64_t secret = 12345ull;
    const uint64_t h = common::Hash::Hash64(std::to_string(secret));

    RandomNum remote(false);
    remote.Sethash("id1", h);
    remote.SetFinalRandomNum("id1", secret + 1ull);
    EXPECT_FALSE(remote.IsRandomValid());
}

TEST(RandomNumBranches, LocalIgnoresSethash) {
    RandomNum local(true);
    local.Sethash("any", 0xDEADBEEFull);
    EXPECT_EQ(local.GetHash(), 0ull);
}

TEST(RandomNumBranches, SethashRejectedAfterOwnerTaken) {
    constexpr uint64_t s = 777ull;
    const uint64_t h = common::Hash::Hash64(std::to_string(s));

    RandomNum remote(false);
    remote.Sethash("first", h);
    remote.Sethash("second", 123ull);
    EXPECT_EQ(remote.GetHash(), h);
}

TEST(RandomNumBranches, RemoteOnTimeBlockClearsValidatedRandom) {
    constexpr uint64_t secret = 424242ull;
    const uint64_t h = common::Hash::Hash64(std::to_string(secret));

    RandomNum remote(false);
    remote.Sethash("node_z", h);
    remote.SetFinalRandomNum("node_z", secret);
    ASSERT_TRUE(remote.IsRandomValid());

    remote.OnTimeBlock(10ull);
    EXPECT_FALSE(remote.IsRandomValid());
}

TEST(RandomNumBranches, LocalOnTimeBlockSecondCallWithSameTsNoops) {
    RandomNum local(true);
    local.OnTimeBlock(100ull);
    ASSERT_TRUE(local.IsRandomValid());
    const uint64_t hash_after_first = local.GetHash();

    local.OnTimeBlock(100ull);
    EXPECT_TRUE(local.IsRandomValid());
    EXPECT_EQ(local.GetHash(), hash_after_first);
}

}  // namespace test
}  // namespace vss
}  // namespace seth
