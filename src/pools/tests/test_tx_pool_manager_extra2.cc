// Additional coverage tests for TxPoolManager with valid network_id and fake kv_sync_:
//   - SyncMinssingHeights: inner loop body (lines 410-440) with valid sharding
//   - SyncMinssingRootHeights: inner loop body (lines 372-402)
//   - SyncBlockWithMaxHeights: full body including AddSyncHeight stub call (lines 459-483)
//   - SyncRootBlockWithMaxHeights: full body including AddSyncHeight stub call (lines 443-457)
//   - HandleSyncPoolsMaxHeight: response path, src=kRootCongressNetworkId (lines 852-880)
//   - HandleSyncPoolsMaxHeight: response path, src=local_des_shard_id (lines 883-910)
//
// Key design: kv_sync_ is a fake non-null ptr; AddSyncHeight is non-virtual (linker stub,
// empty body) so calling it via fake ptr is safe.
// network_id = kConsensusShardBeginNetworkId so SyncMissing* inner loops run.

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "sync/key_value_sync.h"
#include "transport/transport_utils.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/tx_pool_manager.h"
#include "pools/tx_pool.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "network/network_utils.h"

namespace seth {
namespace pools {
namespace test {

// ---------------------------------------------------------------------------
// Fixture: TxPoolManager with valid shard network_id and fake kv_sync_
// ---------------------------------------------------------------------------

class TestTxPoolManagerExtra2 : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_txpm_extra2_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_txpm_extra2_db"));

        prev_net_ = common::GlobalInfo::Instance()->network_id();
        common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);

        // fake non-null kv_sync_: AddSyncHeight is non-virtual → linker stub (empty body) called
        // safely via any non-null pointer.
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

std::shared_ptr<db::Db>        TestTxPoolManagerExtra2::db_       = nullptr;
std::shared_ptr<TxPoolManager> TestTxPoolManagerExtra2::mgr_      = nullptr;
uint32_t                       TestTxPoolManagerExtra2::prev_net_ = common::kInvalidUint32;

// ---------------------------------------------------------------------------
// SyncMinssingHeights with valid network_id: inner loop runs (lines 410-440)
// kv_sync_ = null → SyncBlockWithMaxHeights returns early (no crash)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, SyncMinssingHeights_ValidNetId_InnerLoopRuns) {
    // Set prev_synced_pool_index_ = 2 so BOTH loops run (first: 2..255, second: 0..1)
    mgr_->prev_synced_pool_index_ = 2;
    // Ensure synced_max_heights_[0] > latest_height to trigger SyncBlockWithMaxHeights
    mgr_->synced_max_heights_[0] = 5;  // latest_height() = kInvalidUint64 → condition true
    mgr_->SyncMinssingHeights(common::TimeUtils::TimestampMs());
    // No crash; prev_synced_pool_index_ wrapped around
}

// ---------------------------------------------------------------------------
// SyncMinssingHeights: also covers the "latest_height < synced_max_heights" branch
// (line 416: tx_pool_[i].latest_height() < synced_max_heights_[i])
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, SyncMinssingHeights_LatestBelowMax_TriggersSyncBlock) {
    // Set tx_pool_[0].latest_height_ to a specific value < synced_max_heights_[0]
    mgr_->tx_pool_[0].latest_height_ = 3;
    mgr_->synced_max_heights_[0]     = 10;
    // condition: latest_height() == kInvalidUint64 || latest_height() < synced_max_heights_
    // = false || (3 < 10) = true → SyncBlockWithMaxHeights(0, 10) called → fake kv → stub safe
    mgr_->prev_synced_pool_index_ = 0;
    mgr_->SyncMinssingHeights(common::TimeUtils::TimestampMs());

    // Restore
    mgr_->tx_pool_[0].latest_height_ = common::kInvalidUint64;
    mgr_->synced_max_heights_[0]     = 0;
}

// ---------------------------------------------------------------------------
// SyncMinssingRootHeights: inner loop runs (lines 372-402)
// root_cross_pools_ non-null + valid network_id
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, SyncMinssingRootHeights_ValidNetId_InnerLoopRuns) {
    // root_cross_pools_ is non-null (created in InitCrossPools because
    // network_id=kConsensusShardBeginNetworkId != kRootCongressNetworkId)
    ASSERT_NE(mgr_->root_cross_pools_, nullptr);

    mgr_->root_prev_synced_pool_index_ = 3;
    mgr_->root_synced_max_heights_[0]  = 7;  // triggers SyncRootBlockWithMaxHeights
    mgr_->SyncMinssingRootHeights(common::TimeUtils::TimestampMs());
    // No crash

    mgr_->root_synced_max_heights_[0] = 0;
}

// ---------------------------------------------------------------------------
// SyncBlockWithMaxHeights: valid net_id, fake kv_sync → full body runs (lines 459-483)
// AddSyncHeight is a non-virtual linker stub (empty body) → called safely
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, SyncBlockWithMaxHeights_FakeKvSync_FullBodyRuns) {
    // kv_sync_ is fake non-null → proceeds past the null guard at line 460-462
    // and calls kv_sync_->AddSyncHeight (stub, no-op)
    mgr_->SyncBlockWithMaxHeights(0, 100);
    // No crash
}

// ---------------------------------------------------------------------------
// SyncRootBlockWithMaxHeights: fake kv_sync → full body runs (lines 443-457)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, SyncRootBlockWithMaxHeights_FakeKvSync_FullBodyRuns) {
    // kv_sync_ is fake non-null → proceeds and calls kv_sync_->AddSyncHeight (stub)
    mgr_->SyncRootBlockWithMaxHeights(0, 50);
    // No crash
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response with src = kRootCongressNetworkId →
// processes root pool heights array (lines 852-880)
// root_cross_pools_ non-null; no external calls (no cross_block_mgr_)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_ResponseFromRoot_ProcessesHeights) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kRootCongressNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // Must provide exactly kInvalidPoolIndex heights (line 853 check)
    // Set heights[0]=1000 to trigger the first inner branch (root_synced_max_heights_ update)
    // heights[1]=0 → doesn't trigger (0 is not != kInvalidUint64... actually 0 != UINT64_MAX=true)
    // but 0 < root_synced_max_heights_[1]=0 is false, so no branch taken for i=1
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(i == 0 ? 1000u : 0u);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);

    // root_synced_max_heights_[0] should have been updated to 1000
    EXPECT_EQ(static_cast<uint64_t>(mgr_->root_synced_max_heights_[0]), 1000u);

    // Restore
    mgr_->root_synced_max_heights_[0] = 0;
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response with src = local_des_shard_id →
// processes own pool heights (lines 883-910)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_ResponseFromSelf_ProcessesHeights) {
    auto msg = std::make_shared<transport::TransportMessage>();
    // src = kConsensusShardBeginNetworkId = local_des_shard_id (with our network_id=3)
    msg->header.set_src_sharding_id(network::kConsensusShardBeginNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // heights[0]=500 → triggers first branch (synced_max_heights_[0] = 500)
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(i == 0 ? 500u : 0u);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);

    EXPECT_EQ(static_cast<uint64_t>(mgr_->synced_max_heights_[0]), 500u);

    // Restore
    mgr_->synced_max_heights_[0] = 0;
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response from a different non-root shard →
// accesses cross_pools_[sharding_id] then the do { … } while (0) chain
// followed by cross_block_mgr_->UpdateMaxHeight(sharding_id, update_height).
// cross_block_mgr_ is created unconditionally in the TxPoolManager constructor
// (tx_pool_manager.cc:42) so no mock is needed; we assert on its side effect.
//
// Common setup: src_sharding_id = kConsensusShardBeginNetworkId + 1 (= 4).
//   - 4 < kConsensusShardEndNetworkId (1024) → passes outer guard at line 812.
//   - 4 != local_des_shard_id (== 3 under this fixture) → enters branch at line 817.
//   - 4 != kRootCongressNetworkId (2) → enters the cross_heights branch at 818.
// Each test below exercises a distinct sub-branch of the do { … } while (0)
// chain (cc lines 822-849) plus the trailing UpdateMaxHeight (cc line 850).
// ---------------------------------------------------------------------------

namespace {
constexpr uint32_t kOtherShardForExtra2 = network::kConsensusShardBeginNetworkId + 1u;

// Reset both TxPoolManager and CrossBlockManager state for shard kOtherShardForExtra2
// so successive tests don't leak. Called at the head AND tail of each test.
void ResetCrossStateForOtherShard(TxPoolManager& mgr) {
    mgr.cross_pools_[kOtherShardForExtra2].latest_height_       = common::kInvalidUint64;
    mgr.cross_synced_max_heights_[kOtherShardForExtra2]         = 0;
    mgr.cross_block_mgr_->cross_synced_max_heights_[kOtherShardForExtra2] = 0;
}

std::shared_ptr<transport::TransportMessage> MakeResponseFromOtherShard(
        const std::initializer_list<uint64_t>& cross_heights) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(kOtherShardForExtra2);
    auto* sh = msg->header.mutable_sync_heights();
    sh->set_req(false);
    for (uint64_t h : cross_heights) {
        sh->add_cross_heights(h);
    }
    return msg;
}
}  // namespace

// (1) cross_heights is empty → first break (cc 822-824). update_height retains
// cross_pools_[sid].latest_height() == kInvalidUint64, so UpdateMaxHeight
// returns immediately (height == kInvalidUint64). cross_block_mgr_'s
// max-heights array stays 0.
TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_OtherShard_EmptyCrossHeights_NoUpdate) {
    ResetCrossStateForOtherShard(*mgr_);

    auto msg = MakeResponseFromOtherShard({});
    mgr_->HandleSyncPoolsMaxHeight(msg);

    EXPECT_EQ(
        static_cast<uint64_t>(mgr_->cross_block_mgr_->cross_synced_max_heights_[kOtherShardForExtra2]),
        0u);

    ResetCrossStateForOtherShard(*mgr_);
}

// (2) cross_pools_[sid].latest_height()==kInvalidUint64 AND
// cross_synced_max_heights_[sid] < cross_heights[0] → second branch (cc 827-830).
// update_height = cross_heights[0] = 10, UpdateMaxHeight sets it.
TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_OtherShard_LatestInvalid_BelowMax_SetsHeight) {
    ResetCrossStateForOtherShard(*mgr_);

    auto msg = MakeResponseFromOtherShard({10u});
    mgr_->HandleSyncPoolsMaxHeight(msg);

    EXPECT_EQ(
        static_cast<uint64_t>(mgr_->cross_block_mgr_->cross_synced_max_heights_[kOtherShardForExtra2]),
        10u);

    ResetCrossStateForOtherShard(*mgr_);
}

// (3) cross_heights[0] > cross_pools_[sid].latest_height() + 64 → third branch
// (cc 833-835). update_height capped at latest+64 = 10+64 = 74.
TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_OtherShard_HeightAbove64Cap) {
    ResetCrossStateForOtherShard(*mgr_);
    mgr_->cross_pools_[kOtherShardForExtra2].latest_height_ = 10;

    auto msg = MakeResponseFromOtherShard({200u});  // 200 > 10+64=74 → cap branch
    mgr_->HandleSyncPoolsMaxHeight(msg);

    EXPECT_EQ(
        static_cast<uint64_t>(mgr_->cross_block_mgr_->cross_synced_max_heights_[kOtherShardForExtra2]),
        74u);

    ResetCrossStateForOtherShard(*mgr_);
}

// (4) cross_heights[0] > cross_pools_[sid].latest_height() but NOT above 64 cap
// → fourth branch (cc 838-840). update_height = cross_heights[0] = 50.
TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_OtherShard_SimpleHeightUpdate) {
    ResetCrossStateForOtherShard(*mgr_);
    mgr_->cross_pools_[kOtherShardForExtra2].latest_height_ = 10;

    auto msg = MakeResponseFromOtherShard({50u});  // 10 < 50 ≤ 74 → simple update
    mgr_->HandleSyncPoolsMaxHeight(msg);

    EXPECT_EQ(
        static_cast<uint64_t>(mgr_->cross_block_mgr_->cross_synced_max_heights_[kOtherShardForExtra2]),
        50u);

    ResetCrossStateForOtherShard(*mgr_);
}

// (5) cross_heights[0] <= cross_pools_[sid].latest_height() → none of the
// early `break`s apply → falls through to cc 848 which assigns
// cross_synced_max_heights_[sid] = cross_heights[0]. update_height stays at
// its initial value (cross_pools_[sid].latest_height() = 100), so the trailing
// UpdateMaxHeight(sid, 100) is what lands in cross_block_mgr_.
TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_OtherShard_FallThrough_UsesLatestHeight) {
    ResetCrossStateForOtherShard(*mgr_);
    mgr_->cross_pools_[kOtherShardForExtra2].latest_height_ = 100;

    auto msg = MakeResponseFromOtherShard({50u});  // 50 < 100 → fall through
    mgr_->HandleSyncPoolsMaxHeight(msg);

    // TxPoolManager-owned tracker is set to cross_heights[0] (line 848).
    EXPECT_EQ(
        static_cast<uint64_t>(mgr_->cross_synced_max_heights_[kOtherShardForExtra2]),
        50u);
    // CrossBlockManager-owned tracker is set to the original latest_height (line 850).
    EXPECT_EQ(
        static_cast<uint64_t>(mgr_->cross_block_mgr_->cross_synced_max_heights_[kOtherShardForExtra2]),
        100u);

    ResetCrossStateForOtherShard(*mgr_);
}

// ---------------------------------------------------------------------------
// ConsensusTimerMessage: FlushHeightTree + SyncCrossPool branches fire safely.
// SyncMinssingHeights/SyncMinssingRootHeights are skipped here (covered by their
// own dedicated tests) because they call tx_pool_[i].latest_height() for all 256
// pools, which triggers InitLatestInfo on pools where latest_height_==kInvalidUint64.
// SyncPoolsMaxHeight is skipped (requires Route::Send; now_max_sharding_id_=0 guard
// is sufficient but the route infra is absent in unit tests).
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, ConsensusTimerMessage_ValidNetId_SafeBranchesFire) {
    auto far = common::TimeUtils::TimestampMs() + 9999999lu;
    mgr_->prev_sync_height_tree_tm_ms_ = 0;      // trigger FlushHeightTree
    mgr_->prev_sync_cross_ms_          = 0;      // trigger SyncCrossPool
    mgr_->prev_sync_check_ms_          = far;    // skip SyncMinssingHeights
    mgr_->prev_sync_heights_ms_        = far;    // skip SyncPoolsMaxHeight
    mgr_->ConsensusTimerMessage();
    // No crash; FlushHeightTree and SyncCrossPool branches exercised
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response path, second sub-branch in root case:
// heights[i] > root_cross_pools_[i].latest_height() + 64 → update to +64 (line 867-870)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_ResponseRoot_HeightAbove64Cap) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kRootCongressNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // Set root_cross_pools_[0].latest_height_ = 10
    // heights[0] = 10 + 64 + 1 = 75 → triggers "height > latest+64" branch (line 867)
    mgr_->root_cross_pools_[0].latest_height_ = 10;
    mgr_->root_synced_max_heights_[0]          = 0;

    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(i == 0 ? 75u : 0u);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);
    // root_synced_max_heights_[0] should be capped at 10+64=74
    EXPECT_EQ(static_cast<uint64_t>(mgr_->root_synced_max_heights_[0]), 74u);

    // Restore
    mgr_->root_cross_pools_[0].latest_height_ = common::kInvalidUint64;
    mgr_->root_synced_max_heights_[0]          = 0;
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response path, third sub-branch in local pool case:
// heights[i] > tx_pool_[i].latest_height() + 64 → update to +64 (line 899-902)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_ResponseSelf_HeightAbove64Cap) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kConsensusShardBeginNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // Set tx_pool_[0].latest_height_ = 5
    // heights[0] = 5 + 64 + 1 = 70 → triggers "height > latest+64" branch
    mgr_->tx_pool_[0].latest_height_ = 5;
    mgr_->synced_max_heights_[0]     = 0;

    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(i == 0 ? 70u : 0u);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);
    // synced_max_heights_[0] should be capped at 5+64=69
    EXPECT_EQ(static_cast<uint64_t>(mgr_->synced_max_heights_[0]), 69u);

    // Restore
    mgr_->tx_pool_[0].latest_height_ = common::kInvalidUint64;
    mgr_->synced_max_heights_[0]     = 0;
}

// ---------------------------------------------------------------------------
// HandleSyncPoolsMaxHeight: response path, simple "> latest" (not > latest+64)
// branch (line 904-905)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManagerExtra2, HandleSyncPoolsMaxHeight_ResponseSelf_SimpleHeightUpdate) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->header.set_src_sharding_id(network::kConsensusShardBeginNetworkId);
    msg->header.mutable_sync_heights()->set_req(false);

    // tx_pool_[0].latest_height_ = 5, heights[0] = 10 (> 5 but not > 69)
    mgr_->tx_pool_[0].latest_height_ = 5;
    mgr_->synced_max_heights_[0]     = 0;

    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        msg->header.mutable_sync_heights()->add_heights(i == 0 ? 10u : 0u);
    }

    mgr_->HandleSyncPoolsMaxHeight(msg);
    // synced_max_heights_[0] = 10 (simple update, line 904-905)
    EXPECT_EQ(static_cast<uint64_t>(mgr_->synced_max_heights_[0]), 10u);

    // Restore
    mgr_->tx_pool_[0].latest_height_ = common::kInvalidUint64;
    mgr_->synced_max_heights_[0]     = 0;
}

}  // namespace test
}  // namespace pools
}  // namespace seth
