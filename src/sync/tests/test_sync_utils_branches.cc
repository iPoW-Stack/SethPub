#include <gtest/gtest.h>

#include "common/utils.h"
#include "sync/sync_utils.h"

namespace seth {
namespace sync {
namespace test {

TEST(SyncUtilsBranches, PoolHeightPairCountFormula) {
    constexpr uint32_t expected = 2u * (common::kImmutablePoolSize + 1u);
    EXPECT_EQ(kPoolHeightPairCount, expected);
}

TEST(SyncUtilsBranches, PriorityEnumOrdering) {
    EXPECT_LT(static_cast<uint32_t>(kSyncPriLowest), static_cast<uint32_t>(kSyncHighest));
}

TEST(SyncUtilsBranches, RequestLimitsPositive) {
    EXPECT_GT(kEachRequestMaxSyncKeyCount, 0u);
    EXPECT_GT(kSyncMaxKeyCount, kEachRequestMaxSyncKeyCount);
}

TEST(SyncUtilsBranches, SyncErrorCodeValues) {
    EXPECT_EQ(kSyncSuccess, 0);
    EXPECT_EQ(kSyncError, 1);
    EXPECT_EQ(kSyncKeyExsits, 2);
    EXPECT_EQ(kSyncKeyAdded, 3);
    EXPECT_EQ(kSyncBlockReloaded, 4);
}

TEST(SyncUtilsBranches, SyncPriorityRanksAreOrdered) {
    EXPECT_LT(kSyncPriLowest, kSyncPriLow);
    EXPECT_LT(kSyncPriLow, kSyncNormal);
    EXPECT_LT(kSyncNormal, kSyncHigh);
    EXPECT_LT(kSyncHigh, kSyncHighest);
}

TEST(SyncUtilsBranches, TimingAndCapacityConstants) {
    EXPECT_GT(kSyncTickPeriod, 0u);
    EXPECT_GT(kSyncPacketMaxSize, kEachRequestMaxSyncKeyCount * 100u);
    EXPECT_GE(kMaxSyncMapCapacity, kSyncMaxKeyCount);
    EXPECT_GT(kSyncMaxRetryTimes, 0u);
    EXPECT_GT(kSyncNeighborCount, 0u);
}

TEST(SyncUtilsBranches, RetryPeriodConstantsPositive) {
    EXPECT_GT(kSyncValueRetryPeriod, 0u);
    EXPECT_GT(kTimeoutCheckPeriod, 0u);
}

TEST(SyncUtilsBranches, SyncPriorityEnumCompleteRange) {
    EXPECT_EQ(static_cast<int>(kSyncPriLowest), 0);
    EXPECT_EQ(static_cast<int>(kSyncHighest), 4);
}

}  // namespace test
}  // namespace sync
}  // namespace seth
