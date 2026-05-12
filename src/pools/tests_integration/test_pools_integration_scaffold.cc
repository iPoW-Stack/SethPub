// Scaffold binary for full-stack pools coverage (TxPoolManager, ShardStatistic replay, etc.).
// Built only when -DBUILD_POOLS_INTEGRATION_TEST=ON. Replace the SKIP test with real fixtures
// (Route::Init/Destroy, mocked ElectManager / HotstuffManager, PrefixDb seed data).

#include <gtest/gtest.h>

TEST(PoolsIntegrationScaffold, PlaceholderSkip) {
    GTEST_SKIP()
        << "Enable with -DBUILD_POOLS_INTEGRATION_TEST=ON and add tests. "
           "See src/pools/tests_integration/README.txt for Route, ElectManager, and PrefixDb notes.";
}
