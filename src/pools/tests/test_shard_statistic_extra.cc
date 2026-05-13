// Branch- and function-coverage tests for ShardStatistic methods beyond Init().
//
// Exercises OnNewBlock, ThreadToStatistic, HandleStatistic (up to the
// getLeaderIdFromBlock early-return path), CallTimeBlock, CallNewElectBlock,
// and StatisticWithHeights.
//
// Linker stubs for ElectManager::GetNetworkMembersWithHeight and
// ElectManager::latest_height are provided in test_pools_stubs.cc.

#include <gtest/gtest.h>

#include <memory>

#define private public
#define protected public
#include "db/db.h"
#include "pools/shard_statistic.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "network/network_utils.h"

namespace seth {
namespace pools {
namespace test {

class ShardStatisticExtraTest : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_shard_stat_extra_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_shard_stat_extra_db"));
    }

    static std::shared_ptr<db::Db> db_;

    // Construct with all-null deps (elect_mgr, sec, pools_mgr, contract_mgr)
    ShardStatistic MakeStat() {
        std::shared_ptr<elect::ElectManager>       elect_mgr;
        std::shared_ptr<security::Security>        sec;
        std::shared_ptr<pools::TxPoolManager>      pools_mgr;
        std::shared_ptr<contract::ContractManager> contract_mgr;
        return ShardStatistic(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    }

    // Build a minimal ViewBlockItem for pool pool_idx at height h with
    // qc.network_id set to net_id.
    static std::shared_ptr<view_block::protobuf::ViewBlockItem> MakeVB(
            uint32_t net_id, uint32_t pool_idx, uint64_t h) {
        auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
        vb->mutable_qc()->set_network_id(net_id);
        vb->mutable_qc()->set_pool_index(pool_idx);
        vb->mutable_block_info()->set_height(h);
        return vb;
    }
};

std::shared_ptr<db::Db> ShardStatisticExtraTest::db_ = nullptr;

// ============================================================
// OnNewBlock: !inited_ path — Init() called, fails if bad network_id

#ifndef SETH_UNITTEST
TEST_F(ShardStatisticExtraTest, OnNewBlock_NotInited_InitFails_Coverage) {
    GTEST_SKIP() << "Rebuild with -DXENABLE_CODE_COVERAGE=ON";
}
#else
TEST_F(ShardStatisticExtraTest, OnNewBlock_NotInited_InitFails_NetworkZero) {
    auto stat = MakeStat();
    ASSERT_FALSE(stat.inited_.load());

    auto prev = common::GlobalInfo::Instance()->network_id();
    // network_id = 0 is below kRootCongressNetworkId → Init() returns kPoolsError
    common::GlobalInfo::Instance()->set_network_id(0);

    auto vb = MakeVB(0, 0, 1);
    stat.OnNewBlock(vb);  // Init() fails → inited_ stays false → early return

    EXPECT_FALSE(stat.inited_.load());
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ============================================================
// OnNewBlock: inited_ path — delegates to ThreadToStatistic

TEST_F(ShardStatisticExtraTest, OnNewBlock_Inited_DelegatesToThreadToStatistic) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    ASSERT_EQ(stat.Init(), kPoolsSuccess);
    ASSERT_TRUE(stat.inited_.load());

    // Block from a different shard → ThreadToStatistic returns early (IsSameToLocalShard)
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId + 2, 0, 1);
    stat.OnNewBlock(vb);  // should not crash
    // blocks map stays empty (different network → early return in ThreadToStatistic)
    EXPECT_EQ(stat.pools_consensus_blocks_[0]->blocks.size(), 0u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ============================================================
// ThreadToStatistic: block from a different network → early return

TEST_F(ShardStatisticExtraTest, ThreadToStatistic_DifferentNetwork_EarlyReturn) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // qc.network_id != kConsensusShardBeginNetworkId → IsSameToLocalShard(net_id) == false
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId + 3, 0, 1);
    stat.ThreadToStatistic(vb);

    // Block was NOT stored (returned early at IsSameToLocalShard check)
    EXPECT_EQ(stat.pools_consensus_blocks_[0]->blocks.size(), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ============================================================
// ThreadToStatistic: same network, non-consecutive height → block stored, do-while breaks

TEST_F(ShardStatisticExtraTest, ThreadToStatistic_SameNetwork_NonConsecutive_BlockStored) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // latest_consensus_height_=0, so next expected = 1; height=5 is not consecutive
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 5);
    stat.ThreadToStatistic(vb);

    // Block IS stored in the pool map but HandleStatistic not called
    EXPECT_EQ(stat.pools_consensus_blocks_[0]->blocks.size(), 1u);
    EXPECT_EQ(stat.pools_consensus_blocks_[0]->latest_consensus_height_, 0u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ============================================================
// ThreadToStatistic: consecutive height → HandleStatistic called
// getLeaderIdFromBlock dereferences elect_mgr_ (stub returns nullptr) → returns ""
// → HandleStatistic returns false → do-while breaks
// This exercises the bulk of HandleStatistic (lines 197-483).

TEST_F(ShardStatisticExtraTest, ThreadToStatistic_Consecutive_InvokesHandleStatistic) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // height=1 = latest_consensus_height_(0)+1 → consecutive
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1);
    stat.ThreadToStatistic(vb);  // calls HandleStatistic, which returns false via empty leader_id

    // latest_consensus_height_ stays 0 (HandleStatistic returned false → break before ++height)
    EXPECT_EQ(stat.pools_consensus_blocks_[0]->latest_consensus_height_, 0u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// HandleStatistic: block.has_pool_statistic_height() branch exercised
TEST_F(ShardStatisticExtraTest, HandleStatistic_WithPoolStatisticHeight_Branch) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // Set a pool_statistic_height on the block to enter the corresponding branch
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1);
    vb->mutable_block_info()->set_pool_statistic_height(1);
    stat.ThreadToStatistic(vb);  // HandleStatistic processes has_pool_statistic_height path

    EXPECT_EQ(stat.pools_consensus_blocks_[0]->latest_consensus_height_, 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// HandleStatistic: block.has_elect_statistic() branch exercised
TEST_F(ShardStatisticExtraTest, HandleStatistic_WithElectStatistic_Branch) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1);
    auto* es = vb->mutable_block_info()->mutable_elect_statistic();
    es->set_statistic_height(0);
    es->set_sharding_id(network::kConsensusShardBeginNetworkId);
    stat.ThreadToStatistic(vb);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// HandleStatistic: block with two pool_statistic_height entries to cover the
// statistic_pool_info_.size() >= 2 branch inside HandleStatistic.
TEST_F(ShardStatisticExtraTest, HandleStatistic_TwoStatisticEntries_MaxHeightBranch) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // First block at height=1 with pool_statistic_height=2
    auto vb1 = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1);
    vb1->mutable_block_info()->set_pool_statistic_height(2);
    stat.ThreadToStatistic(vb1);

    // Second block at height=2 with pool_statistic_height=3 → statistic_pool_info_ has 2 entries
    auto vb2 = MakeVB(network::kConsensusShardBeginNetworkId, 0, 2);
    vb2->mutable_block_info()->set_pool_statistic_height(3);
    stat.pools_consensus_blocks_[0]->latest_consensus_height_ = 1;
    stat.ThreadToStatistic(vb2);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ============================================================
// CallTimeBlock

TEST_F(ShardStatisticExtraTest, CallTimeBlock_FirstCall_UpdatesHeight) {
    auto stat = MakeStat();
    EXPECT_EQ(stat.latest_timeblock_height_, 0u);
    stat.CallTimeBlock(0, 10, 42);
    EXPECT_EQ(stat.latest_timeblock_height_, 10u);
    EXPECT_EQ(stat.prev_timeblock_height_, 0u);
}

TEST_F(ShardStatisticExtraTest, CallTimeBlock_SameHeight_NoOp) {
    auto stat = MakeStat();
    stat.CallTimeBlock(0, 10, 42);
    stat.CallTimeBlock(0, 10, 99);  // latest_time_block_height (10) <= current (10) → no-op
    EXPECT_EQ(stat.latest_timeblock_height_, 10u);
}

TEST_F(ShardStatisticExtraTest, CallTimeBlock_LowerHeight_NoOp) {
    auto stat = MakeStat();
    stat.CallTimeBlock(0, 10, 0);
    stat.CallTimeBlock(0, 5, 0);  // 5 <= 10 → no-op
    EXPECT_EQ(stat.latest_timeblock_height_, 10u);
}

TEST_F(ShardStatisticExtraTest, CallTimeBlock_HigherHeight_Advances) {
    auto stat = MakeStat();
    stat.CallTimeBlock(0, 5, 0);
    stat.CallTimeBlock(0, 15, 0);  // 15 > 5 → update
    EXPECT_EQ(stat.latest_timeblock_height_, 15u);
    EXPECT_EQ(stat.prev_timeblock_height_, 5u);
}

// ============================================================
// StatisticWithHeights

TEST_F(ShardStatisticExtraTest, StatisticWithHeights_NotInited_ReturnsError) {
    auto stat = MakeStat();
    ASSERT_FALSE(stat.inited_.load());
    pools::protobuf::ElectStatistic es;
    EXPECT_EQ(stat.StatisticWithHeights(es, 0), kPoolsError);
}

TEST_F(ShardStatisticExtraTest, StatisticWithHeights_Inited_NoEntries_ReturnsError) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    pools::protobuf::ElectStatistic es;
    // statistic_pool_info_ has one entry at height=0; latest_statisticed_height_=0
    // The while loop condition: iter->first > latest_statisticed_height_ (0 > 0) → false → piter stays rend
    // so we reach the iter == rend check → return kPoolsError
    int rc = stat.StatisticWithHeights(es, 0);
    EXPECT_EQ(rc, kPoolsError);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ============================================================
// CallNewElectBlock

TEST_F(ShardStatisticExtraTest, CallNewElectBlock_WrongShardingId_EarlyReturn) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    // Different shard → early return at first check
    stat.CallNewElectBlock(network::kConsensusShardBeginNetworkId + 1, 10);
    EXPECT_EQ(static_cast<uint64_t>(stat.prepare_elect_height_), 0u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

TEST_F(ShardStatisticExtraTest, CallNewElectBlock_LowerHeight_NoOp) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    stat.prepare_elect_height_ = 20;
    stat.CallNewElectBlock(network::kConsensusShardBeginNetworkId, 5);  // 20 >= 5 → no-op
    EXPECT_EQ(static_cast<uint64_t>(stat.prepare_elect_height_), 20u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}
#endif  // SETH_UNITTEST

}  // namespace test
}  // namespace pools
}  // namespace seth
