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

// Test ShardStatistic initialization with different network IDs
TEST_F(ShardStatisticInitTest, InitWithDifferentNetworkIds) {
    std::shared_ptr<elect::ElectManager> elect_mgr;
    std::shared_ptr<security::Security> sec;
    std::shared_ptr<TxPoolManager> pools_mgr;
    std::shared_ptr<contract::ContractManager> contract_mgr;

    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    
    // Test with root congress network ID
    common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
    ShardStatistic stat1(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat1.Init(), kPoolsSuccess);
    
    // Test with consensus shard end network ID
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardEndNetworkId);
    ShardStatistic stat2(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat2.Init(), kPoolsSuccess);
    
    // Test with invalid network ID
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    ShardStatistic stat3(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat3.Init(), kPoolsSuccess);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Test ShardStatistic constructor with null pointers
TEST_F(ShardStatisticInitTest, InitWithNullPointers) {
    std::shared_ptr<elect::ElectManager> elect_mgr;
    std::shared_ptr<security::Security> sec;
    std::shared_ptr<TxPoolManager> pools_mgr;
    std::shared_ptr<contract::ContractManager> contract_mgr;

    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    // Test with null database
    ShardStatistic stat_null_db(elect_mgr, nullptr, sec, pools_mgr, contract_mgr);
    // Should handle null db gracefully
    
    // Test with all null pointers
    ShardStatistic stat_all_null(nullptr, nullptr, nullptr, nullptr, nullptr);
    // Should handle all null pointers gracefully

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Test ShardStatistic multiple initialization calls
TEST_F(ShardStatisticInitTest, MultipleInitCalls) {
    std::shared_ptr<elect::ElectManager> elect_mgr;
    std::shared_ptr<security::Security> sec;
    std::shared_ptr<TxPoolManager> pools_mgr;
    std::shared_ptr<contract::ContractManager> contract_mgr;

    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    ShardStatistic stat(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    
    // First initialization
    EXPECT_EQ(stat.Init(), kPoolsSuccess);
    EXPECT_EQ(stat.latest_statisticed_height(), 0u);
    
    // Second initialization should also succeed
    EXPECT_EQ(stat.Init(), kPoolsSuccess);
    EXPECT_EQ(stat.latest_statisticed_height(), 0u);
    
    // Third initialization
    EXPECT_EQ(stat.Init(), kPoolsSuccess);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Test ShardStatistic with edge case network IDs
TEST_F(ShardStatisticInitTest, InitWithEdgeCaseNetworkIds) {
    std::shared_ptr<elect::ElectManager> elect_mgr;
    std::shared_ptr<security::Security> sec;
    std::shared_ptr<TxPoolManager> pools_mgr;
    std::shared_ptr<contract::ContractManager> contract_mgr;

    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    
    // Test with maximum uint32_t value
    common::GlobalInfo::Instance()->set_network_id(UINT32_MAX);
    ShardStatistic stat_max(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat_max.Init(), kPoolsSuccess);
    
    // Test with zero
    common::GlobalInfo::Instance()->set_network_id(0);
    ShardStatistic stat_zero(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat_zero.Init(), kPoolsSuccess);
    
    // Test with 1
    common::GlobalInfo::Instance()->set_network_id(1);
    ShardStatistic stat_one(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    EXPECT_EQ(stat_one.Init(), kPoolsSuccess);

    common::GlobalInfo::Instance()->set_network_id(prev);
}
#endif

}  // namespace test
}  // namespace pools
}  // namespace seth
