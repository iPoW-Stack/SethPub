#include <gtest/gtest.h>

#include "common/spin_mutex.h"

namespace shardora {
namespace common {
namespace test {

TEST(SpinMutexBranches, TryLockUnlockRoundTrip) {
    SpinMutex m;
    ASSERT_TRUE(m.try_lock());
    ASSERT_FALSE(m.try_lock());
    m.unlock();
    ASSERT_TRUE(m.try_lock());
    m.unlock();
}

TEST(SpinMutexBranches, AutoSpinLockUnlocksOnScopeExit) {
    SpinMutex m;
    {
        AutoSpinLock guard(m);
        ASSERT_FALSE(m.try_lock());
    }
    ASSERT_TRUE(m.try_lock());
    m.unlock();
}

}  // namespace test
}  // namespace common
}  // namespace shardora
