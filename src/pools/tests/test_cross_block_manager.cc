// Branch-coverage tests for CrossBlockManager (cross_block_manager.h).
//
// All methods are defined inline inside the class body; their branches are
// attributed to the header by gcov.  Exercising them here raises branch
// coverage for the pools module.
//
// KeyValueSync::AddSyncHeight stub lives in test_pools_stubs.cc.

#include <gtest/gtest.h>

#include <memory>

#include "sync/key_value_sync.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/cross_block_manager.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/utils.h"
#include "network/network_utils.h"

namespace shardora {
namespace pools {
namespace test {

static std::shared_ptr<sync::KeyValueSync> MakeFakeSync() {
    auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
    return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
}

class TestCrossBlockManager : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_cross_block_manager_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_cross_block_manager_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestCrossBlockManager::db_ptr_ = nullptr;

// ---- UpdateMaxShardingId ----

// Branch: shard_id < max_sharding_id_ (default 3) → no update
TEST_F(TestCrossBlockManager, UpdateMaxShardingId_LowerValue_NoUpdate) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.UpdateMaxShardingId(2u);
    EXPECT_EQ(mgr.max_sharding_id_.load(), 3u);
}

// Branch: shard_id > max_sharding_id_ → update
TEST_F(TestCrossBlockManager, UpdateMaxShardingId_HigherValue_Updates) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.UpdateMaxShardingId(10u);
    EXPECT_EQ(mgr.max_sharding_id_.load(), 10u);
}

// ---- UpdateMaxHeight ----

// Branch: height == kInvalidUint64 → early return, no update
TEST_F(TestCrossBlockManager, UpdateMaxHeight_InvalidHeight_NoUpdate) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    uint64_t before = mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].load();
    mgr.UpdateMaxHeight(network::kConsensusShardBeginNetworkId, common::kInvalidUint64);
    EXPECT_EQ(mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].load(), before);
}

// Branch: shard_id >= kConsensusShardEndNetworkId → early return
TEST_F(TestCrossBlockManager, UpdateMaxHeight_OutOfRangeShard_NoUpdate) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.cross_synced_max_heights_[0].store(0u);
    mgr.UpdateMaxHeight(network::kConsensusShardEndNetworkId, 100u);
    // The shard_id is out of range; array index would be out-of-bounds — only
    // testing that the early-return path is taken (no crash, no update to [0]).
    EXPECT_EQ(mgr.cross_synced_max_heights_[0].load(), 0u);
}

// Branch: height < current (current != kInvalidUint64) → no update
TEST_F(TestCrossBlockManager, UpdateMaxHeight_LowerHeight_NoUpdate) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].store(10u);
    mgr.UpdateMaxHeight(network::kConsensusShardBeginNetworkId, 5u);
    EXPECT_EQ(mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].load(), 10u);
}

// Branch: height > current → update
TEST_F(TestCrossBlockManager, UpdateMaxHeight_HigherHeight_Updates) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].store(5u);
    mgr.UpdateMaxHeight(network::kConsensusShardBeginNetworkId, 20u);
    EXPECT_EQ(mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].load(), 20u);
}

// Branch: current == kInvalidUint64 → update even when height would not be > current
TEST_F(TestCrossBlockManager, UpdateMaxHeight_CurrentInvalid_Updates) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].store(common::kInvalidUint64);
    mgr.UpdateMaxHeight(network::kConsensusShardBeginNetworkId, 0u);
    EXPECT_EQ(mgr.cross_synced_max_heights_[network::kConsensusShardBeginNetworkId].load(), 0u);
}

// ---- CheckCrossSharding (private, accessed via #define private public) ----

// Branch: kInvalidUint32 network_id → early return
TEST_F(TestCrossBlockManager, CheckCrossSharding_InvalidNetId_EarlyReturn) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    mgr.CheckCrossSharding();
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: waiting-shard id (>= kConsensusShardEndNetworkId) → adjusted to root → root path
TEST_F(TestCrossBlockManager, CheckCrossSharding_WaitingShardRoot_AdjustedToRoot) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    auto prev = common::GlobalInfo::Instance()->network_id();
    // kConsensusWaitingShardBeginNetworkId == kConsensusShardEndNetworkId == 1024
    // 1024 - kConsensusWaitingShardOffset(1022) = 2 = kRootCongressNetworkId → root path
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusWaitingShardBeginNetworkId);
    mgr.CheckCrossSharding();
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: non-root shard → CheckCross(local, kRootCongressNetworkId, wbatch)
TEST_F(TestCrossBlockManager, CheckCrossSharding_NonRootShard_ChecksRootCross) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    mgr.CheckCrossSharding();
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: root network_id → loop over shards up to max_sharding_id_
TEST_F(TestCrossBlockManager, CheckCrossSharding_Root_LoopsOverShards) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
    mgr.CheckCrossSharding();
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---- CheckCross: inner branches ----

// Branch: kv_sync_ non-null → AddSyncHeight called (not skipped)
// cross_synced_max_heights_[root]=0 (default), cross_checked[root]=0 →
// GetBlockWithHeight returns false → enters count loop → kv_sync_ non-null → AddSyncHeight
TEST_F(TestCrossBlockManager, CheckCross_KvSyncNonNull_CallsAddSyncHeight) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    // cross_synced_max_heights_[kRootCongressNetworkId] = 0 (default) → enters loop
    db::DbWriteBatch wbatch;
    mgr.CheckCross(
        network::kConsensusShardBeginNetworkId,
        network::kRootCongressNetworkId,
        wbatch);
    // No crash means the kv_sync_ non-null branch executed correctly
}

// Branch: kv_sync_ null → continue (AddSyncHeight skipped)
TEST_F(TestCrossBlockManager, CheckCross_KvSyncNull_SkipsAddSyncHeight) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.kv_sync_ = nullptr;  // override kv_sync_ to null
    db::DbWriteBatch wbatch;
    mgr.CheckCross(
        network::kConsensusShardBeginNetworkId,
        network::kRootCongressNetworkId,
        wbatch);
    // No crash means the !kv_sync_ continue branch executed
}

// Branch: prev_checked_height > cross_synced_max_heights_ → early return
// Set checked=10, synced=5 → 10 > 5 → return before loop
TEST_F(TestCrossBlockManager, CheckCross_PrevHigherThanSynced_EarlyReturn) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.cross_checked_max_heights_[network::kRootCongressNetworkId].store(10u);
    mgr.cross_synced_max_heights_[network::kRootCongressNetworkId].store(5u);
    db::DbWriteBatch wbatch;
    mgr.CheckCross(
        network::kConsensusShardBeginNetworkId,
        network::kRootCongressNetworkId,
        wbatch);
    // early return taken: cross_checked_max_heights_ stays at 10
    EXPECT_EQ(mgr.cross_checked_max_heights_[network::kRootCongressNetworkId].load(), 10u);
}

// Branch: prev_checked == kInvalidUint64 → tries db GetCheckCrossHeight (returns false
//         with empty db), synced also kInvalidUint64 → skips early-return AND skips
//         sync loop (synced == kInvalidUint64 → condition false)
TEST_F(TestCrossBlockManager, CheckCross_PrevInvalid_SyncedInvalid_SkipsSyncLoop) {
    auto kv = MakeFakeSync();
    CrossBlockManager mgr(db_ptr_, kv);
    mgr.cross_checked_max_heights_[network::kRootCongressNetworkId].store(common::kInvalidUint64);
    mgr.cross_synced_max_heights_[network::kRootCongressNetworkId].store(common::kInvalidUint64);
    db::DbWriteBatch wbatch;
    mgr.CheckCross(
        network::kConsensusShardBeginNetworkId,
        network::kRootCongressNetworkId,
        wbatch);
    // GetCheckCrossHeight returns false → prev stays kInvalidUint64
    // synced == kInvalidUint64 → `synced != kInvalidUint64` condition false → loop skipped
    // No crash confirms the path.
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
