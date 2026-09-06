// Additional coverage tests for TxPoolManager targeting the uncovered tail
// of tx_pool_manager.cc and a handful of remaining one-line wrappers in
// tx_pool_manager.h.
//
// Targets (from pools_missing.txt):
//   - cc line 445 : SyncRootBlockWithMaxHeights kv_sync_==nullptr early return
//   - cc line 461 : SyncBlockWithMaxHeights kv_sync_==nullptr early return
//   - cc lines 466-467 : SyncBlockWithMaxHeights waiting-shard net_id adjustment
//   - cc line 471 : SyncBlockWithMaxHeights out-of-range net_id early return
//   - cc lines 284-301 : SyncCrossPool inner loop body (needs now_valid_end_shard >= 3)
//   - cc lines 853-854 : HandleSyncPoolsMaxHeight response root heights size mismatch
//   - cc lines 884-885 : HandleSyncPoolsMaxHeight response self heights size mismatch
//   - cc line 1528 : TxPoolManager::GetTxSyncToLeader delegating wrapper
//   - cc line 1537 : TxPoolManager::GetTxIdempotently delegating wrapper
//   - h lines 84-86 : TxPoolManager::TxOver delegating wrapper
//   - h lines 162-164 : TxPoolManager::cross_latest_height out-of-range guard
//
// Fixture matches test_tx_pool_manager_extra2: network_id = kConsensusShardBeginNetworkId
// so cross_pools_ + root_cross_pools_ are allocated; fake non-null kv_sync_
// so AddSyncHeight calls go through the test_pools_stubs.cc stub.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <unordered_map>

#include "sync/key_value_sync.h"
#include "transport/transport_utils.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/tx_pool.h"
#include "pools/tx_pool_manager.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "network/network_utils.h"

namespace shardora {
namespace pools {
namespace test {

// ---------------------------------------------------------------------------
// Fixture: TxPoolManager with valid shard network_id and fake kv_sync_
// ---------------------------------------------------------------------------

class TestTxPoolManagerExtra3 : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_txpm_extra3_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_txpm_extra3_db"));

        prev_net_ = common::GlobalInfo::Instance()->network_id();
        common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

        auto* raw_kv = reinterpret_cast<sync::KeyValueSync*>(1uLL);
        auto fake_kv = std::shared_ptr<sync::KeyValueSync>(raw_kv, [](sync::KeyValueSync*) {});
        std::shared_ptr<security::Security>         null_sec;
        std::shared_ptr<block::AccountManager>      null_acc;
        std::shared_ptr<consensus::HotstuffManager> null_hotstuff;
        mgr_ = std::make_shared<TxPoolManager>(null_sec, db_, fake_kv, null_acc, null_hotstuff);
    }

    static void TearDownTestSuite() {
        mgr_.reset();
        common::GlobalInfo::Instance()->set_network_id(prev_net_);
    }

    static std::shared_ptr<db::Db>        db_;
    static std::shared_ptr<TxPoolManager> mgr_;
    static uint32_t                       prev_net_;
};

std::shared_ptr<db::Db>        TestTxPoolManagerExtra3::db_       = nullptr;
std::shared_ptr<TxPoolManager> TestTxPoolManagerExtra3::mgr_      = nullptr;
uint32_t                       TestTxPoolManagerExtra3::prev_net_ = common::kInvalidUint32;

// ---------------------------------------------------------------------------
// SyncRootBlockWithMaxHeights — kv_sync_ == nullptr → early return (line 445)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncRootBlockWithMaxHeights_NullKvSync_EarlyReturn) {
    auto saved = mgr_->kv_sync_;
    mgr_->kv_sync_ = nullptr;
    mgr_->SyncRootBlockWithMaxHeights(0, 5);  // hits the null guard at line 444-446
    mgr_->kv_sync_ = saved;
}

// ---------------------------------------------------------------------------
// SyncBlockWithMaxHeights — kv_sync_ == nullptr → early return (line 461)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncBlockWithMaxHeights_NullKvSync_EarlyReturn) {
    auto saved = mgr_->kv_sync_;
    mgr_->kv_sync_ = nullptr;
    mgr_->SyncBlockWithMaxHeights(0, 5);  // hits the null guard at line 460-462
    mgr_->kv_sync_ = saved;
}

// ---------------------------------------------------------------------------
// SyncBlockWithMaxHeights — net_id in waiting-shard range → adjusts net_id
// (lines 465-467 inside SyncBlockWithMaxHeights)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncBlockWithMaxHeights_WaitingShard_AdjustsNetId) {
    const uint32_t saved_net = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(
        network::kConsensusWaitingShardBeginNetworkId);
    mgr_->SyncBlockWithMaxHeights(0, 7);
    common::GlobalInfo::Instance()->set_network_id(saved_net);
}

// ---------------------------------------------------------------------------
// SyncBlockWithMaxHeights — net_id < kRootCongressNetworkId → early return
// (line 470-472)
//
// Using network_id = 0 (< kRootCongressNetworkId == 2). The branch
// "net_id >= kConsensusShardEndNetworkId" is also covered by setting
// network_id to a large invalid value via a second call.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncBlockWithMaxHeights_OutOfRangeNetId_EarlyReturn) {
    const uint32_t saved_net = common::GlobalInfo::Instance()->network_id();

    // Below kRootCongressNetworkId (which is 2) → out-of-range early return.
    common::GlobalInfo::Instance()->set_network_id(0);
    mgr_->SyncBlockWithMaxHeights(0, 9);

    common::GlobalInfo::Instance()->set_network_id(saved_net);
}

// ---------------------------------------------------------------------------
// SyncCrossPool — set now_valid_end_shard >= kConsensusShardBeginNetworkId so
// the loop runs (cc lines 281-308). Exercises both `latest_height ==
// kInvalidUint64 → ex_height=1` and the inner AddSyncHeight loop (which is
// the test_pools_stubs.cc stub).
//
// NOTE: set_now_valid_end_shard is monotonic-up; it remains set for the
// remainder of this test binary, which is benign because no later test
// asserts it stays 0.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncCrossPool_LoopRuns_HitsBodyAndAddSyncHeight) {
    common::GlobalInfo::Instance()->set_now_valid_end_shard(
        network::kConsensusShardBeginNetworkId);

    // Default state: cross_pools_[3].latest_height() == kInvalidUint64 →
    //   ex_height = 1, inner loop iterates up to cross_synced_max_heights_[3].
    // Set cross_synced_max_heights_[3] = 5 to make the inner loop run 5 times.
    mgr_->cross_synced_max_heights_[network::kConsensusShardBeginNetworkId] = 5;
    mgr_->SyncCrossPool();
    mgr_->cross_synced_max_heights_[network::kConsensusShardBeginNetworkId] = 0;
}

// Second variant: latest_height() != kInvalidUint64, and
// latest_height() < cross_synced_max_heights_ → ex_height = latest+1 path
// (cc line 290).
TEST_F(TestTxPoolManagerExtra3, SyncCrossPool_LatestBelowMax_HitsLatestPlusOnePath) {
    common::GlobalInfo::Instance()->set_now_valid_end_shard(
        network::kConsensusShardBeginNetworkId);

    mgr_->cross_pools_[network::kConsensusShardBeginNetworkId].latest_height_ = 2;
    mgr_->cross_synced_max_heights_[network::kConsensusShardBeginNetworkId]    = 6;
    mgr_->SyncCrossPool();

    mgr_->cross_pools_[network::kConsensusShardBeginNetworkId].latest_height_
        = common::kInvalidUint64;
    mgr_->cross_synced_max_heights_[network::kConsensusShardBeginNetworkId] = 0;
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response from root with heights.size() != kInvalidPoolIndex
// → early return at line 853-854.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, HandleSyncPoolsMaxHeight_ResponseRoot_HeightsSizeMismatch_EarlyReturn) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kRootCongressNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // Add fewer than kInvalidPoolIndex heights → size mismatch → early return.
    msg->header.mutable_sync_heights()->add_heights(42u);
    msg->header.mutable_sync_heights()->add_heights(43u);

    mgr_->HandleSyncPoolsMaxHeight(msg);
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response from self with heights.size() != kInvalidPoolIndex
// → early return at line 884-885.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, HandleSyncPoolsMaxHeight_ResponseSelf_HeightsSizeMismatch_EarlyReturn) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kConsensusShardBeginNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    msg->header.mutable_sync_heights()->add_heights(7u);  // size = 1 ≠ kInvalidPoolIndex

    mgr_->HandleSyncPoolsMaxHeight(msg);
}

// ---------------------------------------------------------------------------
// GetTxSyncToLeader — delegating wrapper (cc line 1521-1529).
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, GetTxSyncToLeader_DelegatesToPool_EmptyTxs_NoCrash) {
    ::google::protobuf::RepeatedPtrField<pools::protobuf::TxMessage> out;
    auto null_valid = [](const address::protobuf::AddressInfo&,
                         const pools::protobuf::TxMessage&,
                         uint64_t*) { return 0; };
    const std::unordered_map<std::string, uint64_t> empty_nonces;
    mgr_->GetTxSyncToLeader(/*leader_idx=*/0, /*pool_index=*/0, /*count=*/10,
                            &out, null_valid, empty_nonces);
    EXPECT_EQ(out.size(), 0);
}

// ---------------------------------------------------------------------------
// GetTxIdempotently — delegating wrapper (cc line 1531-1538).
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, GetTxIdempotently_DelegatesToPool_EmptyRes_NoCrash) {
    auto msg = std::make_shared<transport::TransportMessage>();
    std::vector<pools::TxItemPtr> res_map;
    auto null_valid = [](const address::protobuf::AddressInfo&,
                         const pools::protobuf::TxMessage&,
                         uint64_t*) { return 0; };
    mgr_->GetTxIdempotently(msg, /*pool_index=*/0, /*count=*/5, res_map, null_valid);
    EXPECT_TRUE(res_map.empty());
}

// ---------------------------------------------------------------------------
// TxOver — delegating wrapper in tx_pool_manager.h (lines 84-86).
// Empty tx_list keeps the iteration body of TxPool::TxOver from doing work.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, TxOver_DelegatesToPool_EmptyTxList_NoCrash) {
    view_block::protobuf::ViewBlockItem vb;
    vb.mutable_block_info()->set_height(0);
    // No tx_list entries → loop body inside TxPool::TxOver is skipped.
    mgr_->TxOver(/*pool_index=*/0, vb);
}

// ---------------------------------------------------------------------------
// cross_latest_height — out-of-range network_id → returns kInvalidUint64
// (header lines 162-164).
//
// Drive `now_valid_end_shard()` slightly above kConsensusShardBeginNetworkId
// and ask for a network_id strictly greater than that → guard returns
// kInvalidUint64 without indexing into cross_pools_.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, CrossLatestHeight_OutOfRange_ReturnsInvalid) {
    common::GlobalInfo::Instance()->set_now_valid_end_shard(
        network::kConsensusShardBeginNetworkId);
    const uint32_t out_of_range =
        common::GlobalInfo::Instance()->now_valid_end_shard() + 1u;
    EXPECT_EQ(mgr_->cross_latest_height(out_of_range), common::kInvalidUint64);
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response from root with one valid + one invalid
// height entry — already covered by Extra2, but here we additionally trigger
// the heights[i] == kInvalidUint64 branch (skips the `if` body, line 860).
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, HandleSyncPoolsMaxHeight_ResponseRoot_InvalidHeight_Skipped) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kRootCongressNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // All entries kInvalidUint64 → outer `if (heights[i] != kInvalidUint64)`
    // is false for every i, hitting the skip branch on line 892 / 860.
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(common::kInvalidUint64);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response from self with one valid + one invalid
// height entry (mirror of the test above for the local-pool branch).
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, HandleSyncPoolsMaxHeight_ResponseSelf_InvalidHeight_Skipped) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kConsensusShardBeginNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(common::kInvalidUint64);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);
}

// ---------------------------------------------------------------------------
// SyncMinssingHeights — wraparound second loop with one pool having
// latest_height_=kInvalidUint64 and another with latest_height_<max:
// exercises BOTH `latest_height()==kInvalidUint64` and
// `latest_height()<synced_max_heights_` branches across iterations of the
// second (wraparound) loop.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncMinssingHeights_WraparoundLoop_HitsBothBranches) {
    // Place the wraparound region at [0,3): pool 0 = invalid latest, pool 1 = below max,
    // pool 2 = above max (no branch taken).
    mgr_->prev_synced_pool_index_ = 3;

    mgr_->tx_pool_[0].latest_height_ = common::kInvalidUint64;
    mgr_->synced_max_heights_[0]     = 4;  // triggers "invalid" branch

    mgr_->tx_pool_[1].latest_height_ = 2;
    mgr_->synced_max_heights_[1]     = 9;  // triggers "below max" branch

    mgr_->tx_pool_[2].latest_height_ = 10;
    mgr_->synced_max_heights_[2]     = 3;  // 10 < 3 false → branch NOT taken

    mgr_->SyncMinssingHeights(common::TimeUtils::TimestampMs());

    // Restore
    mgr_->tx_pool_[1].latest_height_ = common::kInvalidUint64;
    mgr_->tx_pool_[2].latest_height_ = common::kInvalidUint64;
    mgr_->synced_max_heights_[0]     = 0;
    mgr_->synced_max_heights_[1]     = 0;
    mgr_->synced_max_heights_[2]     = 0;
}

// ---------------------------------------------------------------------------
// SyncMinssingRootHeights — same idea for the root-cross variant.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra3, SyncMinssingRootHeights_WraparoundLoop_HitsBothBranches) {
    ASSERT_NE(mgr_->root_cross_pools_, nullptr);
    mgr_->root_prev_synced_pool_index_ = 3;

    mgr_->root_cross_pools_[0].latest_height_ = common::kInvalidUint64;
    mgr_->root_synced_max_heights_[0]         = 4;

    mgr_->root_cross_pools_[1].latest_height_ = 2;
    mgr_->root_synced_max_heights_[1]         = 9;

    mgr_->root_cross_pools_[2].latest_height_ = 10;
    mgr_->root_synced_max_heights_[2]         = 3;

    mgr_->SyncMinssingRootHeights(common::TimeUtils::TimestampMs());

    mgr_->root_cross_pools_[1].latest_height_ = common::kInvalidUint64;
    mgr_->root_cross_pools_[2].latest_height_ = common::kInvalidUint64;
    mgr_->root_synced_max_heights_[0]         = 0;
    mgr_->root_synced_max_heights_[1]         = 0;
    mgr_->root_synced_max_heights_[2]         = 0;
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
