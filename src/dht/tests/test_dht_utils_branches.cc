#include <gtest/gtest.h>

#include "dht/dht_utils.h"

namespace seth {
namespace dht {
namespace test {

TEST(DhtUtilsBranches, DhtErrorCodeEnumComplete) {
    EXPECT_EQ(kDhtSuccess, 0);
    EXPECT_EQ(kDhtError, 1);
    EXPECT_EQ(kDhtInvalidNat, 2);
    EXPECT_EQ(kDhtNodeJoined, 3);
    EXPECT_EQ(kDhtInvalidBucket, 4);
    EXPECT_EQ(kDhtDesInvalid, 5);
    EXPECT_EQ(kDhtIpInvalid, 6);
    EXPECT_EQ(kDhtKeyInvalid, 7);
    EXPECT_EQ(kDhtClientMode, 8);
    EXPECT_EQ(kNodeInvalid, 9);
    EXPECT_EQ(kDhtKeyHashError, 10);
    EXPECT_EQ(kDhtGetBucketError, 11);
    EXPECT_EQ(kDhtMaxNeiborsError, 12);
    EXPECT_EQ(kDhtKeyInvalidCountry, 13);
}

TEST(DhtUtilsBranches, BootstrapTagValues) {
    EXPECT_EQ(kBootstrapNoInit, 0);
    EXPECT_EQ(kBootstrapInit, 1);
    EXPECT_EQ(kBootstrapInitWithConfNodes, 2);
}

TEST(DhtUtilsBranches, NatTypeOrdered) {
    EXPECT_LT(static_cast<int>(kNatTypeUnknown), static_cast<int>(kNatTypeFullcone));
    EXPECT_LT(static_cast<int>(kNatTypeFullcone), static_cast<int>(kNatTypeAddressLimit));
    EXPECT_LT(static_cast<int>(kNatTypeAddressLimit), static_cast<int>(kNatTypePortLimit));
}

TEST(DhtUtilsBranches, NodeJoinWayStartsAtUnknown) {
    EXPECT_EQ(kJoinFromUnknown, 0);
}

TEST(DhtUtilsBranches, NodeJoinWayEnumSequential) {
    EXPECT_EQ(kJoinFromUnknown, 0);
    EXPECT_EQ(kJoinFromBootstrapRes, 1);
    EXPECT_EQ(kJoinFromRefreshNeigberRequest, 2);
    EXPECT_EQ(kJoinFromRefreshNeigberResponse, 3);
    EXPECT_EQ(kJoinFromElectBlock, 4);
    EXPECT_EQ(kJoinFromNetworkDetection, 5);
    EXPECT_EQ(kJoinFromBootstrapReq, 6);
    EXPECT_EQ(kJoinFromConnect, 7);
    EXPECT_EQ(kJoinFromDetection, 8);
    EXPECT_EQ(kJoinFromUniversal, 9);
    EXPECT_EQ(kJoinFromInit, 10);
}

TEST(DhtUtilsBranches, RefreshNeighborCountsConsistent) {
    EXPECT_EQ(kRefreshNeighborsDefaultCount, kRefreshNeighborsCount);
    EXPECT_GT(kRefreshNeighborsBloomfilterBitCount, 0u);
    EXPECT_GT(kRefreshNeighborsBloomfilterHashCount, 0u);
}

TEST(DhtUtilsBranches, DhtScaleConstantsOrdered) {
    EXPECT_GT(kDhtNearestNodesCount, 0u);
    EXPECT_GT(kDhtMinReserveNodes, 0u);
    EXPECT_EQ(kDhtKeySize, 32u);
    EXPECT_GT(kDhtMaxNeighbors, kDhtNearestNodesCount);
}

}  // namespace test
}  // namespace dht
}  // namespace seth
