// ShardStatistic::Init with an empty DB: only succeeds when libpools is built
// with SETH_UNITTEST (see src/pools/CMakeLists.txt under XENABLE_CODE_COVERAGE),
// which enables a synthetic PoolStatisticTxInfo when PrefixDb has no tag yet.

#include <gtest/gtest.h>

#include <memory>

#include "common/global_info.h"
#include "db/db.h"
#include "network/network_utils.h"
#include "pools/shard_statistic.h"

namespace seth {
namespace pools {
namespace test {

class ShardStatisticInitTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        (void)system("rm -rf ./test_shard_statistic_init_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_shard_statistic_init_db"));
    }

    static std::shared_ptr<db::Db> db_;
};

std::shared_ptr<db::Db> ShardStatisticInitTest::db_ = nullptr;

#ifndef SETH_UNITTEST
TEST_F(ShardStatisticInitTest, InitWithoutTagRequiresCoverageBuild) {
    GTEST_SKIP() << "Rebuild with -DXENABLE_CODE_COVERAGE=ON (e.g. bash build.sh pools_test Debug coverage)";
}
#else
TEST_F(ShardStatisticInitTest, InitWithoutPersistedTagUsesSyntheticLayout) {
    std::shared_ptr<elect::ElectManager> elect_mgr;
    std::shared_ptr<security::Security> sec;
    std::shared_ptr<TxPoolManager> pools_mgr;
    std::shared_ptr<contract::ContractManager> contract_mgr;

    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    ShardStatistic stat(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat.Init(), kPoolsSuccess);
    EXPECT_EQ(stat.latest_statisticed_height(), 0u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}
#endif

}  // namespace test
}  // namespace pools
}  // namespace seth
