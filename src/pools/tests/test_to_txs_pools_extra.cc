// Branch- and function-coverage tests for ToTxsPools methods not yet
// exercised in test_to_txs_pools.cc:
//
//   ToTxsPools::NewBlock
//   ToTxsPools::ThreadToStatistic (consecutive / non-consecutive heights,
//                                   block with normal_to)
//   ToTxsPools::HandleElectJoinVerifyVec (non-root shard, root shard)
//   ToTxsPools::CreateToTxWithHeights (prev > leader, all-equal, max >
//                                       consensus, acc_amount_map empty)
//
// ThreadToStatistic and HandleElectJoinVerifyVec are private; accessed via
// #define private public.  The linker stub for AccountManager::GetAccountInfo
// lives in test_pools_stubs.cc.

#include <gtest/gtest.h>

#include <memory>
#include <vector>

#include "block/account_manager.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/to_txs_pools.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/utils.h"
#include "network/network_utils.h"
#include "protos/bls.pb.h"
#include "protos/pools.pb.h"
#include <protos/view_block.pb.h>

namespace shardora {
namespace pools {
namespace test {

class TestToTxsPoolsExtra : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_to_txs_pools_extra_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_to_txs_pools_extra_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;

    // Construct a ToTxsPools with null pools_mgr and acc_mgr so
    // LoadLatestHeights() is skipped.
    ToTxsPools MakePool() {
        std::shared_ptr<pools::TxPoolManager> null_mgr;
        std::shared_ptr<block::AccountManager> null_acc;
        return ToTxsPools(db_ptr_, "", 0, null_mgr, null_acc);
    }

    // Build a minimal ViewBlockItem for pool pool_idx at the given height.
    static std::shared_ptr<view_block::protobuf::ViewBlockItem> MakeVB(
            uint32_t pool_idx, uint64_t height) {
        auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
        vb->mutable_qc()->set_pool_index(pool_idx);
        vb->mutable_block_info()->set_height(height);
        return vb;
    }
};

std::shared_ptr<db::Db> TestToTxsPoolsExtra::db_ptr_ = nullptr;

// ============================================================
// ToTxsPools::NewBlock

// NewBlock delegates to ThreadToStatistic (TEST_NO_CROSS is not defined here).
// With a basic view_block and a valid network_id, it should not crash.
TEST_F(TestToTxsPoolsExtra, NewBlock_BasicCall_NoError) {
    auto pool = MakePool();
    auto vb = MakeVB(0, 1);
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.NewBlock(vb);
    common::GlobalInfo::Instance()->set_network_id(prev);
    // No crash: NewBlock forwarded to ThreadToStatistic successfully
}

// ============================================================
// ToTxsPools::ThreadToStatistic

// Branch: consecutive height (pool_consensus_heihgts_[0]+1 == block.height())
// → pool_consensus_heihgts_[0] advances to 1
TEST_F(TestToTxsPoolsExtra, ThreadToStatistic_ConsecutiveHeight_AdvancesConsensus) {
    auto pool = MakePool();
    ASSERT_EQ(pool.pool_consensus_heihgts_[0], 0u);
    auto vb = MakeVB(0, 1);  // 0+1 == 1 → advance
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.ThreadToStatistic(vb);
    common::GlobalInfo::Instance()->set_network_id(prev);
    EXPECT_EQ(pool.pool_consensus_heihgts_[0], 1u);
}

// Branch: non-consecutive height → pool_consensus_heihgts_[0] stays at 0
TEST_F(TestToTxsPoolsExtra, ThreadToStatistic_NonConsecutiveHeight_NoAdvancement) {
    auto pool = MakePool();
    auto vb = MakeVB(0, 5);  // 0+1 != 5, and height 1 not in added_heights_
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.ThreadToStatistic(vb);
    common::GlobalInfo::Instance()->set_network_id(prev);
    EXPECT_EQ(pool.pool_consensus_heihgts_[0], 0u);
}

// Branch: block.has_normal_to() → prev_to_heights_ gets populated
TEST_F(TestToTxsPoolsExtra, ThreadToStatistic_WithNormalTo_SetsPrevToHeights) {
    auto pool = MakePool();
    ASSERT_EQ(pool.prev_to_heights_, nullptr);

    auto vb = MakeVB(0, 1);
    // Attach normal_to with kInvalidPoolIndex zero heights
    auto* normal_to = vb->mutable_block_info()->mutable_normal_to();
    auto* to_heights = normal_to->mutable_to_heights();
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        to_heights->add_heights(0);
    }

    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.ThreadToStatistic(vb);
    common::GlobalInfo::Instance()->set_network_id(prev);
    EXPECT_NE(pool.prev_to_heights_, nullptr);
}

// ============================================================
// ToTxsPools::HandleElectJoinVerifyVec

// Branch: shard_id != kRootCongressNetworkId → return, verify_reqs unchanged
TEST_F(TestToTxsPoolsExtra, HandleElectJoinVerifyVec_NonRootShard_NotPushed) {
    auto pool = MakePool();
    bls::protobuf::JoinElectInfo info;
    info.set_shard_id(network::kConsensusShardBeginNetworkId);  // != root (2)
    std::string serialized;
    ASSERT_TRUE(info.SerializeToString(&serialized));

    std::vector<bls::protobuf::JoinElectInfo> reqs;
    pool.HandleElectJoinVerifyVec(serialized, reqs);
    EXPECT_TRUE(reqs.empty());
}

// Branch: shard_id == kRootCongressNetworkId → push_back into verify_reqs
TEST_F(TestToTxsPoolsExtra, HandleElectJoinVerifyVec_RootShard_Pushed) {
    auto pool = MakePool();
    bls::protobuf::JoinElectInfo info;
    info.set_shard_id(network::kRootCongressNetworkId);  // == 2
    std::string serialized;
    ASSERT_TRUE(info.SerializeToString(&serialized));

    std::vector<bls::protobuf::JoinElectInfo> reqs;
    pool.HandleElectJoinVerifyVec(serialized, reqs);
    ASSERT_EQ(reqs.size(), 1u);
    EXPECT_EQ(reqs[0].shard_id(), (uint32_t)network::kRootCongressNetworkId);
}

// ============================================================
// ToTxsPools::CreateToTxWithHeights

// Helper: build a ShardToTxItem with kInvalidPoolIndex heights all set to val.
static pools::protobuf::ShardToTxItem MakeHeights(uint64_t val) {
    pools::protobuf::ShardToTxItem item;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        item.add_heights(val);
    }
    return item;
}

// Branch: prev_heights(0) > leader_heights(0) → kPoolsError at loop i=0
TEST_F(TestToTxsPoolsExtra, CreateToTxWithHeights_PrevHigherThanLeader_Error) {
    auto pool = MakePool();
    // prev_to_heights_ with heights(0)=5, rest=0
    auto prev_member = std::make_shared<pools::protobuf::ShardToTxItem>();
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        prev_member->add_heights(i == 0 ? 5 : 0);
    }
    pool.prev_to_heights_ = prev_member;

    auto leader = MakeHeights(0);  // all zeros
    // prev_arg is empty → will be filled from prev_to_heights_ (heights(0)=5)
    pools::protobuf::ShardToTxItem prev_arg;
    pools::protobuf::ToTxMessage to_tx;
    EXPECT_EQ(pool.CreateToTxWithHeights(
        network::kConsensusShardBeginNetworkId, 0, &prev_arg, leader, to_tx),
        kPoolsError);
}

// Branch: all prev == leader → heights_valid=false → no empty to_tx
TEST_F(TestToTxsPoolsExtra, CreateToTxWithHeights_AllEqualHeights_Success) {
    auto pool = MakePool();
    pool.prev_to_heights_ = std::make_shared<pools::protobuf::ShardToTxItem>(MakeHeights(0));

    auto leader = MakeHeights(0);
    pools::protobuf::ShardToTxItem prev_arg;  // empty → filled from prev_to_heights_
    pools::protobuf::ToTxMessage to_tx;
    EXPECT_EQ(pool.CreateToTxWithHeights(
        network::kConsensusShardBeginNetworkId, 0, &prev_arg, leader, to_tx),
        kPoolsError);
}

// Branch: max_height > pool_consensus_heihgts_[0] → kPoolsError
// leader.heights(0)=5 > prev.heights(0)=0 so heights_valid=true,
// but 5 > pool_consensus_heihgts_[0](0) → early return
TEST_F(TestToTxsPoolsExtra, CreateToTxWithHeights_MaxAboveConsensus_Error) {
    auto pool = MakePool();
    pool.prev_to_heights_ = std::make_shared<pools::protobuf::ShardToTxItem>(MakeHeights(0));

    // leader heights(0)=5, rest=0
    pools::protobuf::ShardToTxItem leader;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        leader.add_heights(i == 0 ? 5 : 0);
    }
    // pool_consensus_heihgts_[0] stays 0 → 5 > 0 → error
    pools::protobuf::ShardToTxItem prev_arg;
    pools::protobuf::ToTxMessage to_tx;
    EXPECT_EQ(pool.CreateToTxWithHeights(
        network::kConsensusShardBeginNetworkId, 0, &prev_arg, leader, to_tx),
        kPoolsError);
}

// Branch: acc_amount_map empty but heights advanced → kPoolsError (no to_tx)
// leader.heights(0)=1 but network_txs_pools_[0] has no entry → map stays empty
TEST_F(TestToTxsPoolsExtra, CreateToTxWithHeights_EmptyAccAmountMap_Success) {
    auto pool = MakePool();
    pool.prev_to_heights_ = std::make_shared<pools::protobuf::ShardToTxItem>(MakeHeights(0));

    pools::protobuf::ShardToTxItem leader;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        leader.add_heights(i == 0 ? 1 : 0);
    }
    // Ensure pool_consensus_heihgts_[0] >= leader.heights(0)
    pool.pool_consensus_heihgts_[0] = 5;

    // network_txs_pools_[0] is empty → acc_amount_map stays empty → empty ToTx OK
    pools::protobuf::ShardToTxItem prev_arg;
    pools::protobuf::ToTxMessage to_tx;
    EXPECT_EQ(pool.CreateToTxWithHeights(
        network::kConsensusShardBeginNetworkId, 0, &prev_arg, leader, to_tx),
        kPoolsError);
}

// ToTxsPools::ClearLeaderToHeights (inline in to_txs_pools.h) clears leader snapshot.
TEST_F(TestToTxsPoolsExtra, ClearLeaderToHeights_ClearsStore) {
    auto pool = MakePool();
    auto dummy = std::make_shared<pools::protobuf::ShardToTxItem>();
    pool.StoreLeaderToHeights(dummy);
    pool.ClearLeaderToHeights();
    EXPECT_EQ(pool.LoadLeaderToHeights(), nullptr);
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
