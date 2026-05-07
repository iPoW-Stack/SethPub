#include <gtest/gtest.h>

#include <limits>

#include "elect/elect_utils.h"

namespace seth {
namespace elect {
namespace test {

TEST(ElectConstantsBranches, InvalidMemberIndexIsMaxUint32) {
    EXPECT_EQ(kInvalidMemberIndex, (std::numeric_limits<uint32_t>::max)());
}

TEST(ElectConstantsBranches, ElectTimingOffsetsPositive) {
    EXPECT_GT(kElectAvailableJoinTime, 0ull);
    EXPECT_GT(kElectAvailableTolerateTime, 0ull);
    EXPECT_GE(kWaitingNodesGetTimeoffsetMilli, 0ull);
}

TEST(ElectConstantsBranches, BloomAndHopLimitsAreOrdered) {
    EXPECT_LE(kElectHopLimit, 100u);
    EXPECT_GT(kElectNeighborCount, 0u);
    EXPECT_LT(kBloomfilterSize, kBloomfilterWaitingSize);
    EXPECT_GE(kBloomfilterWaitingHashCount, kBloomfilterHashCount);
}

}  // namespace test
}  // namespace elect
}  // namespace seth
