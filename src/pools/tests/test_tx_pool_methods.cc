// Branch-coverage tests for TxPool methods defined in tx_pool.cc.
//
// Exercises SyncMissingBlocks, InitHeightTree, UpdateSyncedHeight, and
// UpdateLatestInfo branches that are reachable without Init() or real tx
// queues.  Uses the same #define private public technique so internal
// state can be seeded directly.  The linker stub lives in test_pools_stubs.cc.

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "sync/key_value_sync.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/tx_pool.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/utils.h"
#include "network/network_utils.h"

namespace seth {
namespace pools {
namespace test {

// Fake non-null shared_ptr<KeyValueSync>: non-virtual calls go to our stub
// in test_pools_stubs.cc; the pointer is never actually dereferenced for data.
static std::shared_ptr<sync::KeyValueSync> MakeFakeSync() {
    auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
    return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
}

class TestTxPoolMethods : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_tx_pool_methods_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_tx_pool_methods_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;

    // Set pool to a consistent baseline: valid db and shard network_id
    void SetUpPool(TxPool& pool) {
        pool.db_ = db_ptr_;
        pool.pool_index_ = 0;
        pool.latest_height_ = common::kInvalidUint64;
        pool.synced_height_ = 0;
        pool.prev_synced_height_ = 0;
    }
};

std::shared_ptr<db::Db> TestTxPoolMethods::db_ptr_ = nullptr;

// ---- SyncMissingBlocks ----

// Branch: height_tree_ptr_ null AND has_missing_height_=false → return 0 immediately
TEST_F(TestTxPoolMethods, SyncMissingBlocks_NullTree_NotMissing_ReturnsZero) {
    TxPool pool;
    pool.height_tree_ptr_ = nullptr;
    pool.has_missing_height_ = false;
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
}

// Branch: height_tree_ptr_ null AND has_missing_height_=true → calls InitHeightTree
//         → kInvalidUint32 network_id → returns without setting tree → return 0
TEST_F(TestTxPoolMethods, SyncMissingBlocks_NullTree_MissingFlag_InvalidNetId_ReturnsZero) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = nullptr;
    pool.has_missing_height_ = true;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
    EXPECT_EQ(pool.height_tree_ptr_, nullptr);  // InitHeightTree returned early
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: height_tree_ptr_ null AND has_missing_height_=true → InitHeightTree
//         → out-of-shard-range network_id → returns without setting tree → return 0
TEST_F(TestTxPoolMethods, SyncMissingBlocks_NullTree_MissingFlag_OutOfRange_ReturnsZero) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = nullptr;
    pool.has_missing_height_ = true;
    auto prev = common::GlobalInfo::Instance()->network_id();
    // kRootCongressNetworkId - 1 is below the valid shard range
    common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId - 1);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: height_tree_ptr_ valid AND latest_height_ == kInvalidUint64 → return 0
TEST_F(TestTxPoolMethods, SyncMissingBlocks_ValidTree_InvalidLatestHeight_ReturnsZero) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.latest_height_ = common::kInvalidUint64;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: valid tree, all heights synced → no missing → has_missing_height_=false, return 0
// A tree with Set(0) and latest_height_=0 has no missing heights; invalid_heights=={0}
// from GetMissingHeights but net_id check stops before sync → synced_count=0 →
// has_missing_height_ set to false.
TEST_F(TestTxPoolMethods, SyncMissingBlocks_AllSynced_ClearsMissingFlag) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    pool.latest_height_ = 0;
    pool.has_missing_height_ = true;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.SyncMissingBlocks(0);
    // synced_count==0 → has_missing_height_=false
    EXPECT_FALSE(pool.has_missing_height_.load());
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---- InitHeightTree ----

// Branch: kInvalidUint32 → early return, tree stays null
TEST_F(TestTxPoolMethods, InitHeightTree_InvalidNetId_TreeStaysNull) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = nullptr;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    pool.InitHeightTree();
    EXPECT_EQ(pool.height_tree_ptr_, nullptr);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: waiting shard network_id → adjusted to base shard, tree created
TEST_F(TestTxPoolMethods, InitHeightTree_WaitingShardNetId_CreatesTree) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = nullptr;
    pool.latest_height_ = 0;
    auto prev = common::GlobalInfo::Instance()->network_id();
    // Use waiting-shard offset of kConsensusShardBeginNetworkId
    uint32_t waiting_id = network::kConsensusShardBeginNetworkId +
                          network::kConsensusWaitingShardOffset;
    common::GlobalInfo::Instance()->set_network_id(waiting_id);
    pool.InitHeightTree();
    EXPECT_NE(pool.height_tree_ptr_, nullptr);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: valid shard id → tree created
TEST_F(TestTxPoolMethods, InitHeightTree_ValidShard_CreatesTree) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = nullptr;
    pool.latest_height_ = 0;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.InitHeightTree();
    EXPECT_NE(pool.height_tree_ptr_, nullptr);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---- UpdateSyncedHeight ----

// Branch: null height_tree_ptr_ → no-op
TEST_F(TestTxPoolMethods, UpdateSyncedHeight_NullTree_NoOp) {
    TxPool pool;
    pool.height_tree_ptr_ = nullptr;
    pool.synced_height_ = 5;
    pool.UpdateSyncedHeight();
    EXPECT_EQ(pool.synced_height_, 5u);
}

// Branch: non-null tree, Valid(synced_height_+1) returns false → no advance
TEST_F(TestTxPoolMethods, UpdateSyncedHeight_ValidTreeNoAdvance) {
    TxPool pool;
    SetUpPool(pool);
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    pool.latest_height_ = 5;
    pool.synced_height_ = 0;
    pool.UpdateSyncedHeight();
    // height 1 was not Set → Valid(1) = false → loop breaks → synced_height_ stays 0
    EXPECT_EQ(pool.synced_height_, 0u);
}

// ---- UpdateLatestInfo ----

// Branch: kv_sync_ == null → return kInvalidUint64
TEST_F(TestTxPoolMethods, UpdateLatestInfo_NullKvSync_ReturnsInvalid) {
    TxPool pool;
    pool.kv_sync_ = nullptr;
    EXPECT_EQ(pool.UpdateLatestInfo(1, "hash", "prehash", 0), common::kInvalidUint64);
}

// Branch: kv_sync_ non-null, height_tree_ptr_ already set, sequential height
//         → synced_height_ advances and returns new synced_height_
TEST_F(TestTxPoolMethods, UpdateLatestInfo_SequentialHeight_AdvancesSyncedHeight) {
    TxPool pool;
    SetUpPool(pool);
    pool.kv_sync_         = MakeFakeSync();
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    pool.latest_height_ = 0;
    pool.synced_height_ = 0;
    pool.prev_synced_height_ = 0;
    // height=1, synced_height_+1 == height → should advance synced_height_ to 1
    auto result = pool.UpdateLatestInfo(1, "h1", "ph0", 42);
    EXPECT_EQ(pool.latest_height_, 1u);
    EXPECT_EQ(result, 1u);
}

// Branch: kv_sync_ non-null, height skips → SyncBlock called (non-sequential)
TEST_F(TestTxPoolMethods, UpdateLatestInfo_NonSequentialHeight_CallsSyncBlock) {
    TxPool pool;
    SetUpPool(pool);
    pool.kv_sync_         = MakeFakeSync();
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    pool.latest_height_ = 0;
    pool.synced_height_ = 0;
    // height=5, synced_height_(0)+1 != 5 → goes to SyncBlock() path
    auto result = pool.UpdateLatestInfo(5, "h5", "ph0", 42);
    EXPECT_EQ(pool.latest_height_, 5u);
    // synced_height_ stays 0 (SyncBlock was called but height_tree doesn't have 1..4)
    EXPECT_EQ(result, 0u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
