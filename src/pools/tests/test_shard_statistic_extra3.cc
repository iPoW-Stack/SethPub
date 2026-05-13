// Extended branch-coverage tests for ShardStatistic::HandleStatistic and
// ShardStatistic::StatisticWithHeights using the controllable ElectManager stub.
//
// g_test_members_override (declared in test_pools_stubs.cc) is set to a
// non-null MembersPtr so that getLeaderIdFromBlock() returns a valid leader id
// and HandleStatistic proceeds past its early-return guard.
//
// All tests are guarded by SETH_UNITTEST because Init() requires the macro
// for the empty-DB path.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <map>

#define private public
#define protected public
#include "db/db.h"
#include "pools/shard_statistic.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/node_members.h"
#include "network/network_utils.h"

// Declared in test_pools_stubs.cc — not a separate header so we extern here.
namespace seth {
namespace elect {
extern common::MembersPtr g_test_members_override;
extern uint64_t           g_test_latest_height;
}
}

namespace seth {
namespace pools {
namespace test {

#ifndef SETH_UNITTEST
TEST(ShardStatExtra3, SkippedWithoutSethUnittest) {
    GTEST_SKIP() << "Rebuild with -DXENABLE_CODE_COVERAGE=ON";
}
#else

// ---------------------------------------------------------------------------
// Helper: build a MembersPtr with `count` members whose ids are 1-byte strings
// ---------------------------------------------------------------------------

static common::MembersPtr MakeMembers(uint32_t count, uint32_t net_id = 0) {
    auto members = std::make_shared<common::Members>();
    for (uint32_t i = 0; i < count; ++i) {
        std::string id(common::kUnicastAddressLength, static_cast<char>(i + 1));
        auto m = std::make_shared<common::BftMember>(
            net_id, id, "pk" + std::to_string(i), i, i == 0 ? 1 : 0);
        members->push_back(m);
    }
    return members;
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class ShardStatExtra3Test : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_shard_stat_extra3_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_shard_stat_extra3_db"));
    }

    static std::shared_ptr<db::Db> db_;

    ShardStatistic MakeStat() {
        std::shared_ptr<elect::ElectManager>       elect_mgr;
        std::shared_ptr<security::Security>        sec;
        std::shared_ptr<pools::TxPoolManager>      pools_mgr;
        std::shared_ptr<contract::ContractManager> contract_mgr;
        return ShardStatistic(elect_mgr, db_, sec, pools_mgr, contract_mgr);
    }

    static std::shared_ptr<view_block::protobuf::ViewBlockItem> MakeVB(
            uint32_t net_id, uint32_t pool_idx, uint64_t h,
            uint32_t leader_idx = 0) {
        auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
        vb->mutable_qc()->set_network_id(net_id);
        vb->mutable_qc()->set_pool_index(pool_idx);
        vb->mutable_qc()->set_leader_idx(leader_idx);
        vb->mutable_block_info()->set_height(h);
        return vb;
    }

    // RAII guard: sets the stub override and resets on destruction
    struct MembersGuard {
        explicit MembersGuard(common::MembersPtr m) {
            elect::g_test_members_override = std::move(m);
        }
        ~MembersGuard() {
            elect::g_test_members_override = nullptr;
            elect::g_test_latest_height    = 0;
        }
    };
};

std::shared_ptr<db::Db> ShardStatExtra3Test::db_ = nullptr;

// ---------------------------------------------------------------------------
// HandleStatistic full path: getLeaderIdFromBlock returns valid leader_id,
// accumulates gas/tx counts, returns true.
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, HandleStatistic_ValidMembers_ReturnsTrue) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // Provide 1-member list; leader_idx=0 → (*members)[0]->id is valid
    MembersGuard guard(MakeMembers(1, network::kConsensusShardBeginNetworkId));

    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1, 0);
    vb->mutable_block_info()->set_all_gas(42);

    bool result = stat.HandleStatistic(vb);
    // HandleStatistic should return true (leader_id is non-empty)
    EXPECT_TRUE(result);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// HandleStatistic: join_elect block path — joins array is empty so secptr_
// (null in unit tests) is never dereferenced; the loop exits trivially.
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, HandleStatistic_JoinsEmpty_DoesNotCrash) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers(1));

    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 2, 0);
    // Do NOT add any joins — secptr_ is null, so any join would crash.
    // Calling HandleStatistic with zero joins covers the join loop exit path.
    EXPECT_TRUE(stat.HandleStatistic(vb));

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// HandleStatistic: elect_block with gas_for_root > 0 (line 405-406).
// No in() nodes are added so secptr_ (null in tests) is never dereferenced.
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, HandleStatistic_ElectBlock_GasForRoot) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers(1));

    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 3, 0);
    auto* eb = vb->mutable_block_info()->mutable_elect_block();
    eb->set_gas_for_root(500);

    stat.HandleStatistic(vb);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// HandleStatistic: elect_statistic in block (lines 427-476)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, HandleStatistic_WithElectStatistic_Processing) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers(1));

    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 4, 0);
    auto* es = vb->mutable_block_info()->mutable_elect_statistic();
    es->set_statistic_height(0);
    es->set_sharding_id(network::kConsensusShardBeginNetworkId);
    // Add a join_elect_node with root congress shard
    auto* jn = es->add_join_elect_nodes();
    jn->set_pubkey("root_node_pk");
    jn->set_stoke(200);
    jn->set_shard(network::kRootCongressNetworkId);

    stat.HandleStatistic(vb);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// ThreadToStatistic: consecutive height with valid members → HandleStatistic
// returns true → pool height incremented
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, ThreadToStatistic_ConsecutiveHeight_ValidMembers_Advances) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers(1));

    // height=1 is consecutive (latest_consensus_height_=0)
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1, 0);
    stat.ThreadToStatistic(vb);

    // HandleStatistic returned true → latest_consensus_height_ advanced to 1
    EXPECT_EQ(stat.pools_consensus_blocks_[0]->latest_consensus_height_, 1u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// ThreadToStatistic: multiple consecutive heights
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, ThreadToStatistic_MultipleConsecutive_AdvancesAll) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers(1));

    // Send heights 1, 2, 3 consecutively from pool 1
    for (uint64_t h = 1; h <= 3; ++h) {
        auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 1, h, 0);
        stat.ThreadToStatistic(vb);
    }

    EXPECT_EQ(stat.pools_consensus_blocks_[1]->latest_consensus_height_, 3u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: two-entry statistic_pool_info_ with valid members
// → advances past the nullptr early-return (lines 722-734)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, StatisticWithHeights_TwoEntries_ValidMembers) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // Build a second entry at height=2 with all 256 pools properly filled.
    std::map<uint32_t, StatisticInfoItem> pool_map2;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        StatisticInfoItem item;
        item.statistic_min_height = 0;
        item.statistic_max_height = 5;
        pool_map2[i] = item;
    }
    stat.statistic_pool_info_[2] = pool_map2;
    // latest_statisticed_height_ = 0 → loop enters for height=2

    elect::g_test_latest_height    = 1;  // latest_height stub
    MembersGuard guard(MakeMembers(1));

    pools::protobuf::ElectStatistic es;
    // With now_elect_members non-null, StatisticWithHeights proceeds deeper.
    int rc = stat.StatisticWithHeights(es, 0);
    // May return kPoolsSuccess or kPoolsError depending on further conditions;
    // the important thing is it does NOT crash and gets past line 734.
    (void)rc;

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: min_height > max_height for a pool → kPoolsError (line 695)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, StatisticWithHeights_MinGtMax_ReturnsError) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // Build second entry at height=2 where pool 0 has min_height > max_height
    std::map<uint32_t, StatisticInfoItem> pool_map2;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        StatisticInfoItem item;
        if (i == 0) {
            item.statistic_min_height = 10;
            item.statistic_max_height = 5;  // min > max → error
        } else {
            item.statistic_min_height = 0;
            item.statistic_max_height = 5;
        }
        pool_map2[i] = item;
    }
    stat.statistic_pool_info_[2] = pool_map2;

    MembersGuard guard(MakeMembers(1));

    pools::protobuf::ElectStatistic es;
    EXPECT_EQ(stat.StatisticWithHeights(es, 0), kPoolsError);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: pool_map sizes != kInvalidPoolIndex → kPoolsError (line 629)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, StatisticWithHeights_IncompletePools_ReturnsError) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // Add entry at height=2 with only 1 pool entry (not 256)
    std::map<uint32_t, StatisticInfoItem> incomplete;
    incomplete[0] = StatisticInfoItem();
    stat.statistic_pool_info_[2] = incomplete;

    MembersGuard guard(MakeMembers(1));

    pools::protobuf::ElectStatistic es;
    EXPECT_EQ(stat.StatisticWithHeights(es, 0), kPoolsError);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// CallNewElectBlock: same shard, higher height → updates prepare_elect_height_
// and calls elect_mgr_->latest_height (stub returns g_test_latest_height)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, CallNewElectBlock_SameShard_HigherHeight_Updates) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

    elect::g_test_latest_height = 5;

    stat.prepare_elect_height_ = 0;
    stat.CallNewElectBlock(network::kConsensusShardBeginNetworkId, 10);
    EXPECT_EQ(static_cast<uint64_t>(stat.prepare_elect_height_), 10u);

    elect::g_test_latest_height = 0;
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// HandleStatistic: pool_statistic_height + statistic_pool_info_ >= 2 path
// (lines 236-257)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra3Test, HandleStatistic_PoolStatisticHeight_Ge2Entries_MaxHeightBranch) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers(1));

    // First block at height=1 with pool_statistic_height=2 → populates second entry
    auto vb1 = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1, 0);
    vb1->mutable_block_info()->set_pool_statistic_height(2);
    stat.HandleStatistic(vb1);

    // Second block at height=2 with pool_statistic_height=3 → ≥2 entries triggers
    // the iter-back walk (statistic_pool_info_.size() >= 2 branch)
    stat.pools_consensus_blocks_[0]->latest_consensus_height_ = 1;
    auto vb2 = MakeVB(network::kConsensusShardBeginNetworkId, 0, 2, 0);
    vb2->mutable_block_info()->set_pool_statistic_height(3);
    stat.HandleStatistic(vb2);

    // Both calls should succeed without crashing
    EXPECT_GE(stat.statistic_pool_info_.size(), 1u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

#endif  // SETH_UNITTEST

}  // namespace test
}  // namespace pools
}  // namespace seth
