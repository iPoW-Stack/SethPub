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

TEST(ElectConstantsBranches, ElectErrorCodeEnumValues) {
    EXPECT_EQ(kElectSuccess, 0);
    EXPECT_EQ(kElectError, 1);
    EXPECT_EQ(kElectJoinUniversalError, 2);
    EXPECT_EQ(kElectJoinShardFailed, 3);
    EXPECT_EQ(kElectNoBootstrapNodes, 4);
    EXPECT_EQ(kElectNetworkJoined, 5);
    EXPECT_EQ(kElectNetworkNotJoined, 6);
}

TEST(ElectConstantsBranches, FtsAndShardRatesPositive) {
    EXPECT_GT(kFtsWeedoutDividRate, 0u);
    EXPECT_GT(kInvalidShardNodesRate, 0u);
    EXPECT_GT(kEachShardMaxTps, 0u);
}

TEST(ElectConstantsBranches, MinShardingAndTolerateRates) {
    EXPECT_GE(kMinShardingNetworkNodesCount, 1u);
    EXPECT_LE(kTolerateLeaderBackupFiffRate, 100u);
    EXPECT_GT(kSmoothGradientAmount, 0ull);
}

TEST(ElectConstantsBranches, BroadcastAndHopToLayer) {
    EXPECT_NE(kElectBroadcastIgnBloomfilterHop, kElectBroadcastStopTimes);
    EXPECT_LE(kElectHopToLayer, kElectHopLimit);
}

}  // namespace test
}  // namespace elect
}  // namespace seth
