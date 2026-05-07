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

}  // namespace test
}  // namespace sync
}  // namespace seth
