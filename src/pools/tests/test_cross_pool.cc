// Branch-coverage tests for cross_pool.cc (114 lines) and root_cross_pool.cc (31 lines).
//
// Link note: linker stubs for non-virtual external symbols are centralised in
// test_pools_stubs.cc — do not add them here.

#include <gtest/gtest.h>

#include <memory>

// Must include the real sync header so the class declaration is in scope
// (the stub definition lives in test_pools_stubs.cc).
#include "sync/key_value_sync.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/cross_pool.h"
#include "pools/root_cross_pool.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "network/network_utils.h"

namespace seth {
namespace pools {
namespace test {

class TestCrossPool : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_cross_pool_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_cross_pool_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;

    // A non-null shared_ptr<KeyValueSync> backed by a fake address (never dereferenced).
    // Calling non-virtual methods through this pointer resolves to our stubs (empty body).
    static std::shared_ptr<sync::KeyValueSync> MakeFakeSync() {
        auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
        return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
    }
};

std::shared_ptr<db::Db> TestCrossPool::db_ptr_ = nullptr;

// ---- CrossPool: default construction ----

TEST_F(TestCrossPool, DefaultConstructorLeavesAllNulls) {
    CrossPool pool;
    EXPECT_EQ(pool.latest_height(), common::kInvalidUint64);
    EXPECT_EQ(pool.kv_sync_, nullptr);
    EXPECT_EQ(pool.height_tree_ptr_, nullptr);
}

// ---- CrossPool::Init with null kv_sync ----

TEST_F(TestCrossPool, InitWithNullKvSyncSetsHeightTreePtr) {
    CrossPool pool;
    std::shared_ptr<sync::KeyValueSync> null_sync = nullptr;
    pool.Init(network::kConsensusShardBeginNetworkId, db_ptr_, null_sync);
    EXPECT_EQ(pool.kv_sync_, nullptr);
    // InitHeightTree() was called → height_tree_ptr_ is populated
    EXPECT_NE(pool.height_tree_ptr_, nullptr);
}

// ---- SyncMissingBlocks: early-return branches ----

// Branch 1 T: network_id == kInvalidUint32 → return 0 immediately
TEST_F(TestCrossPool, SyncMissingBlocks_InvalidNetworkId_ReturnsZero) {
    CrossPool pool;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch 2 T: des_sharding_id_ == network_id → return 0
TEST_F(TestCrossPool, SyncMissingBlocks_SameShard_ReturnsZero) {
    CrossPool pool;
    constexpr uint32_t kShard = network::kConsensusShardBeginNetworkId;
    pool.des_sharding_id_ = kShard;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(kShard);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch 3 T: kv_sync_ == nullptr → return 0
TEST_F(TestCrossPool, SyncMissingBlocks_NullKvSync_ReturnsZero) {
    CrossPool pool;
    constexpr uint32_t kRemote = network::kConsensusShardBeginNetworkId + 1;
    constexpr uint32_t kLocal  = network::kConsensusShardBeginNetworkId;
    pool.des_sharding_id_ = kRemote;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(kLocal);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);  // kv_sync_ is null
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch 4 T: kv_sync_ non-null, height_tree_ptr_ == nullptr → return 0
TEST_F(TestCrossPool, SyncMissingBlocks_NullHeightTree_ReturnsZero) {
    CrossPool pool;
    constexpr uint32_t kRemote = network::kConsensusShardBeginNetworkId + 1;
    constexpr uint32_t kLocal  = network::kConsensusShardBeginNetworkId;
    pool.des_sharding_id_ = kRemote;
    pool.kv_sync_         = MakeFakeSync();
    pool.height_tree_ptr_ = nullptr;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(kLocal);
    EXPECT_EQ(pool.SyncMissingBlocks(0), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch 5 T: latest_height_ == kInvalidUint64 → AddSyncHeight stub called, returns 1
TEST_F(TestCrossPool, SyncMissingBlocks_InvalidLatestHeight_ReturnsOne) {
    CrossPool pool;
    constexpr uint32_t kRemote = network::kConsensusShardBeginNetworkId + 1;
    constexpr uint32_t kLocal  = network::kConsensusShardBeginNetworkId;
    pool.des_sharding_id_ = kRemote;
    pool.kv_sync_         = MakeFakeSync();
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        kRemote, 0, common::kInvalidUint64, db_ptr_);
    pool.latest_height_ = common::kInvalidUint64;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(kLocal);
    // AddSyncHeight stub (empty) is invoked; function returns 1
    EXPECT_EQ(pool.SyncMissingBlocks(0), 1u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---- UpdateLatestInfo inline branches ----

// Returns kInvalidUint64 when kv_sync_ is null
TEST_F(TestCrossPool, UpdateLatestInfo_NullKvSync_ReturnsInvalid) {
    CrossPool pool;
    EXPECT_EQ(pool.UpdateLatestInfo(10), common::kInvalidUint64);
}

// With fake kv_sync_ and height_tree_ptr_, advances latest_height_
TEST_F(TestCrossPool, UpdateLatestInfo_UpdatesLatestHeight) {
    CrossPool pool;
    pool.kv_sync_         = MakeFakeSync();
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    pool.synced_height_ = 0;
    pool.latest_height_ = common::kInvalidUint64;
    pool.UpdateLatestInfo(1);
    EXPECT_EQ(pool.latest_height_, 1u);
}

// ---- FlushHeightTree inline branches ----

// null height_tree_ptr_ → no-op
TEST_F(TestCrossPool, FlushHeightTree_NullTree_NoOp) {
    CrossPool pool;
    db::DbWriteBatch batch;
    pool.FlushHeightTree(batch);
}

// non-null height_tree_ptr_ → FlushToDb called
TEST_F(TestCrossPool, FlushHeightTree_ValidTree_FlushesToDb) {
    CrossPool pool;
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    db::DbWriteBatch batch;
    pool.FlushHeightTree(batch);
}

// ---- SyncBlock inline branch ----

// null height_tree_ptr_ → immediate return
TEST_F(TestCrossPool, SyncBlock_NullTree_IsNoOp) {
    CrossPool pool;
    pool.SyncBlock();
}

// ---- UpdateSyncedHeight inline branch ----

TEST_F(TestCrossPool, UpdateSyncedHeight_NullTree_IsNoOp) {
    CrossPool pool;
    pool.UpdateSyncedHeight();
}

// ---- RootCrossPool ----

TEST_F(TestCrossPool, RootCrossPoolDefaultShardIsRoot) {
    RootCrossPool pool;
    EXPECT_EQ(pool.des_sharding_id_, network::kRootCongressNetworkId);
}

TEST_F(TestCrossPool, RootCrossPoolInitDelegatesToCrossPoolInit) {
    RootCrossPool pool;
    std::shared_ptr<sync::KeyValueSync> null_sync = nullptr;
    pool.Init(0u, db_ptr_, null_sync);
    EXPECT_NE(pool.height_tree_ptr_, nullptr);
    EXPECT_EQ(pool.pool_index_, 0u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
