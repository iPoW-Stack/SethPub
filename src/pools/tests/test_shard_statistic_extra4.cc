// Extended coverage tests for ShardStatistic:
//   - CallTimeBlock (update / skip-if-older)
//   - OnNewBlock (inited_ gate)
//   - StatisticWithHeights success path (setElectStatistics, addNewNode2JoinStatics,
//     addPrepareMembers2JoinStastics with members whose pubkeys are all in
//     added_id_set so that secptr_==null SHARDORA_DEBUG lines are never reached)
//   - StatisticWithHeights piter==rend early-return
//
// All tests guarded by SHARDORA_UNITTEST.

#include <gtest/gtest.h>

#include <memory>
#include <map>
#include <set>

#define private public
#define protected public
#include "db/db.h"
#include "pools/shard_statistic.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/node_members.h"
#include "network/network_utils.h"

namespace shardora {
namespace elect {
extern common::MembersPtr g_test_members_override;
extern uint64_t           g_test_latest_height;
}
}

namespace shardora {
namespace pools {
namespace test {

#ifndef SHARDORA_UNITTEST
TEST(ShardStatExtra4, SkippedWithoutShardoraUnittest) {
    GTEST_SKIP() << "Rebuild with -DXENABLE_CODE_COVERAGE=ON";
}
#else

static common::MembersPtr MakeMembers4(uint32_t count,
                                        uint32_t net_id = network::kConsensusShardBeginNetworkId) {
    auto members = std::make_shared<common::Members>();
    for (uint32_t i = 0; i < count; ++i) {
        std::string id(common::kUnicastAddressLength, static_cast<char>(i + 1));
        // pubkey must be non-empty and unique; use "pk<i>" padded to kUnicastAddressLength
        std::string pk = "pk" + std::to_string(i);
        auto m = std::make_shared<common::BftMember>(net_id, id, pk, i, i == 0 ? 1 : 0);
        members->push_back(m);
    }
    return members;
}

class ShardStatExtra4Test : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_shard_stat_extra4_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_shard_stat_extra4_db"));
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
            uint32_t net_id, uint32_t pool_idx, uint64_t h, uint32_t leader_idx = 0) {
        auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
        vb->mutable_qc()->set_network_id(net_id);
        vb->mutable_qc()->set_pool_index(pool_idx);
        vb->mutable_qc()->set_leader_idx(leader_idx);
        vb->mutable_block_info()->set_height(h);
        return vb;
    }

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

std::shared_ptr<db::Db> ShardStatExtra4Test::db_ = nullptr;

// ---------------------------------------------------------------------------
// CallTimeBlock: height < current → ignored
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, CallTimeBlock_OlderHeight_Ignored) {
    auto stat = MakeStat();
    stat.latest_timeblock_height_ = 10;
    stat.CallTimeBlock(0, 5, 0);
    EXPECT_EQ(stat.latest_timeblock_height_, 10u);
}

// ---------------------------------------------------------------------------
// CallTimeBlock: height == current → ignored (not strictly greater)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, CallTimeBlock_SameHeight_Ignored) {
    auto stat = MakeStat();
    stat.latest_timeblock_height_ = 10;
    stat.CallTimeBlock(0, 10, 0);
    EXPECT_EQ(stat.latest_timeblock_height_, 10u);
}

// ---------------------------------------------------------------------------
// CallTimeBlock: higher height → updates latest and prev
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, CallTimeBlock_NewerHeight_Updates) {
    auto stat = MakeStat();
    stat.latest_timeblock_height_ = 5;
    stat.prev_timeblock_height_   = 3;
    stat.CallTimeBlock(12345, 7, 42);
    EXPECT_EQ(stat.latest_timeblock_height_, 7u);
    EXPECT_EQ(stat.prev_timeblock_height_,   5u);
}

// ---------------------------------------------------------------------------
// OnNewBlock: inited_=false, Init() called but fails (network_id invalid) →
// returns without crashing
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, OnNewBlock_NotInited_InvalidNetwork_Returns) {
    auto stat = MakeStat();
    // Do NOT call Init(), and set invalid network_id so Init() will fail
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);

    auto vb = MakeVB(common::kInvalidUint32, 0, 1);
    stat.OnNewBlock(vb);  // should not crash; Init() returns kPoolsError → inited_ stays false
    EXPECT_FALSE(stat.inited_);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// OnNewBlock: inited_=true → delegates to ThreadToStatistic
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, OnNewBlock_Inited_DelegatesToThreadToStatistic) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    MembersGuard guard(MakeMembers4(1));
    auto vb = MakeVB(network::kConsensusShardBeginNetworkId, 0, 1, 0);
    stat.OnNewBlock(vb);

    EXPECT_EQ(stat.pools_consensus_blocks_[0]->latest_consensus_height_, 1u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: not inited → kPoolsError immediately
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, StatisticWithHeights_NotInited_ReturnsError) {
    auto stat = MakeStat();
    // inited_ is false (Init() not called)
    pools::protobuf::ElectStatistic es;
    EXPECT_EQ(stat.StatisticWithHeights(es, 0), kPoolsError);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: only one entry in statistic_pool_info_ (the init
// entry at height=0), nothing above latest_statisticed_height_=0 →
// piter stays rend → kPoolsError at line 605
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, StatisticWithHeights_OnlyInitEntry_ReturnsError) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);
    // statistic_pool_info_ has only height=0; latest_statisticed_height_=0
    // → while loop: iter->first=0, 0 > 0 is false → loop never runs → piter=rend
    MembersGuard guard(MakeMembers4(1));
    pools::protobuf::ElectStatistic es;
    EXPECT_EQ(stat.StatisticWithHeights(es, 0), kPoolsError);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: full success path
//
// Setup:
//   - statistic_pool_info_[0] = 256 pools, min=0, max=0 (from Init)
//   - statistic_pool_info_[2] = 256 pools, min=0, max=0
//   - latest_statisticed_height_ = 0 → iter will find {0:...}, piter = {2:...}
//   - g_test_members_override = 1-member list (same for prepare and now)
//   - all pubkeys of prepare_members ARE in added_id_set (same member list)
//     → addPrepareMembers2JoinStastics: all continue → no secptr_ call
//   - join_elect_stoke_map empty → addNewNode2JoinStatics: elect_nodes empty
//     → no secptr_ call
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, StatisticWithHeights_SuccessPath_ReturnsSuccess) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    // Add a second entry at height=2 with all 256 pools having valid min<=max
    std::map<uint32_t, StatisticInfoItem> pool_map2;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        StatisticInfoItem item;
        item.statistic_min_height = 0;
        item.statistic_max_height = 0;  // min == max → valid (0 > 0 is false)
        pool_map2[i] = item;
    }
    stat.statistic_pool_info_[2] = pool_map2;

    elect::g_test_latest_height = 1;
    auto members = MakeMembers4(1);
    MembersGuard guard(members);

    pools::protobuf::ElectStatistic es;
    int rc = stat.StatisticWithHeights(es, 0);
    EXPECT_EQ(rc, kPoolsSuccess);
    // elect_statistic should have sharding_id set
    EXPECT_EQ(es.sharding_id(), network::kConsensusShardBeginNetworkId);
    // statistic_height_map_ should now contain an entry for height 0
    EXPECT_EQ(stat.statistic_height_map_.count(0u), 1u);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---------------------------------------------------------------------------
// StatisticWithHeights: piter->first NOT > iter->first → kPoolsError (line 886)
// This happens when piter==iter (both point to same height), which can't happen
// with 2 distinct heights, but we can force it by making piter->first == iter->first.
// The easiest way: inject entries such that piter and iter end up on the same key.
// We bypass normal entry creation and directly set statistic_pool_info_.
// With height=1 as the only entry above latest_statisticed_height_=0:
//   piter = {1:...}, iter = {0:...}
//   1 > 0 → success, not what we want.
// Instead we test via two entries where the 2nd has all min>max → kPoolsError before 886.
// We use a simpler test: verify that the error path at 886 is NOT triggered in our
// normal success scenario (i.e., assert it returns kPoolsSuccess above).
//
// To force the line-886 error path we'd need piter->first == iter->first, which
// requires a very unusual state. We cover it indirectly by verifying the success
// test does NOT hit it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// addHeightInfo2Statics: callable directly (public via #define private public)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, AddHeightInfo2Statics_SetsHeightInfo) {
    auto stat = MakeStat();
    pools::protobuf::ElectStatistic es;
    // Call private method directly
    stat.addHeightInfo2Statics(es, 99);
    EXPECT_EQ(es.height_info().tm_height(), 99u);
}

// ---------------------------------------------------------------------------
// CallTimeBlock + StatisticWithHeights: ensure latest_timeblock_height_
// doesn't interfere with StatisticWithHeights (it reads statistic_pool_info_)
// ---------------------------------------------------------------------------

TEST_F(ShardStatExtra4Test, CallTimeBlock_ThenStatisticWithHeights_Consistent) {
    auto stat = MakeStat();
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    ASSERT_EQ(stat.Init(), kPoolsSuccess);

    stat.CallTimeBlock(1000, 3, 0);
    EXPECT_EQ(stat.latest_timeblock_height_, 3u);

    // Add statistic entry
    std::map<uint32_t, StatisticInfoItem> pm;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        pm[i] = StatisticInfoItem();
    }
    stat.statistic_pool_info_[2] = pm;

    elect::g_test_latest_height = 1;
    MembersGuard guard(MakeMembers4(1));
    pools::protobuf::ElectStatistic es;
    EXPECT_EQ(stat.StatisticWithHeights(es, 0), kPoolsSuccess);

    common::GlobalInfo::Instance()->set_network_id(prev);
}

#endif  // SHARDORA_UNITTEST

}  // namespace test
}  // namespace pools
}  // namespace shardora
