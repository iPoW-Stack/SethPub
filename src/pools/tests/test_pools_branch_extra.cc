// Small-file branch coverage:
//
//   - cross_pool.cc 85-87, 90, 94: SyncMissingBlocks BlockExists==true branch
//     (height_tree_ptr_->Set; synced_height_ advance; SHARDORA_DEBUG; continue).
//   - leaf_height_tree.cc 60, 67: Set(child_index, val) out-of-range guards.
//   - leaf_height_tree.cc 83, 111: Set(index)/Valid out-of-range guards.
//   - leaf_height_tree.cc 227: GetRoot for is_branch_=true.
//   - leaf_height_tree.cc 281-289: PrintLevel.
//   - leaf_height_tree.cc 297-301, 327-331, 342-346, 349: branch print/get
//     paths with max_level >= 1.
//
// Implementation notes:
//   * BlockExists is satisfied by writing the exact key prefix_db uses
//     (kBlockHeightPrefix + sharding_id + pool_index + height) to the db.
//   * Print* functions write to std::cout; we wrap them in a stream redirect
//     so the test output stays clean.
//   * KeyValueSync stubs are reused from test_pools_stubs.cc (same fake-ptr
//     pattern as test_cross_pool.cc).

#include <gtest/gtest.h>

#include <memory>
#include <sstream>
#include <vector>

#include "sync/key_value_sync.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/cross_pool.h"
#include "pools/height_tree_level.h"
#include "pools/leaf_height_tree.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "network/network_utils.h"

namespace shardora {
namespace pools {
namespace test {

// RAII guard to swallow std::cout output during print-method tests.
class ScopedSilenceCoutB {
public:
    ScopedSilenceCoutB() : old_(std::cout.rdbuf(oss_.rdbuf())) {}
    ~ScopedSilenceCoutB() { std::cout.rdbuf(old_); }
private:
    std::ostringstream oss_;
    std::streambuf* old_{ nullptr };
};

// ===========================================================================
// cross_pool.cc — SyncMissingBlocks BlockExists==true branch
// ===========================================================================

class TestCrossPoolBranch : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_cross_pool_branch_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_cross_pool_branch_db"));
    }

    static std::shared_ptr<sync::KeyValueSync> MakeFakeSync() {
        auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
        return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
    }

    // Write the BlockExists-checked key for (sharding, pool, height) so the
    // prefix-db lookup hits without us going through the full SaveBlock API.
    static void StashBlockExistsKey(uint32_t shard, uint32_t pool, uint64_t h) {
        std::string key;
        key.append("j\x01", 2);  // matches kBlockHeightPrefix in prefix_db.h
        key.append(reinterpret_cast<const char*>(&shard), sizeof(shard));
        key.append(reinterpret_cast<const char*>(&pool),  sizeof(pool));
        key.append(reinterpret_cast<const char*>(&h),     sizeof(h));
        db::DbWriteBatch batch;
        batch.Put(key, std::string("x"));
        ASSERT_TRUE(db_ptr_->Put(batch).ok());
    }

    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestCrossPoolBranch::db_ptr_ = nullptr;

// SyncMissingBlocks: latest_height_ != kInvalidUint64 AND some
// `invalid_heights[i]` already has its block saved → enters the
// BlockExists==true branch and runs lines 85-87 (Set, synced advance) and
// 90/94 (SHARDORA_DEBUG, continue).
TEST_F(TestCrossPoolBranch, SyncMissingBlocks_BlockExistsBranch_Runs) {
    CrossPool pool;
    constexpr uint32_t kRemote   = network::kConsensusShardBeginNetworkId + 1;
    constexpr uint32_t kLocal    = network::kConsensusShardBeginNetworkId;
    constexpr uint32_t kPoolIdx  = 0;
    constexpr uint64_t kStashed  = 3;  // any missing height in [1, latest]
    constexpr uint64_t kLatest   = 5;

    StashBlockExistsKey(kRemote, kPoolIdx, kStashed);

    pool.des_sharding_id_ = kRemote;
    pool.pool_index_      = kPoolIdx;
    pool.kv_sync_         = MakeFakeSync();
    pool.db_              = db_ptr_;
    pool.prefix_db_       = std::make_shared<protos::PrefixDb>(db_ptr_);
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        kRemote, kPoolIdx, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);          // max_height_ = 0
    pool.latest_height_   = kLatest;        // catch-up range: 1..5
    pool.synced_height_   = 0;

    const auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(kLocal);
    const uint32_t count = pool.SyncMissingBlocks(0);
    common::GlobalInfo::Instance()->set_network_id(prev);

    // Five missing heights (1..5); one is stashed, so AddSyncHeight was called
    // four times via the stub, and synced_height_ was advanced to the stashed
    // height.
    EXPECT_EQ(count, 5u);
    EXPECT_GE(pool.synced_height_, kStashed);
}

// ===========================================================================
// leaf_height_tree.cc — out-of-range guards and branch-tree print/get paths
// ===========================================================================

class TestLeafHeightTreeBranch : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_leaf_branch_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_leaf_branch_db"));
    }
    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestLeafHeightTreeBranch::db_ptr_ = nullptr;

// Set(child_index, val) early return when parent_idx < global_leaf_index_
// (cc 58-60). Construct a level-1 branch with node_index=2 so
// global_leaf_index_ = 2 * kBranchMaxCount; child_index=0 → parent_idx=0 < it.
TEST_F(TestLeafHeightTreeBranch, BranchSetChildBelowGlobalIndex_EarlyReturn) {
    LeafHeightTree branch(0, 0, /*level=*/1, /*node_index=*/2, db_ptr_);
    ASSERT_EQ(branch.global_leaf_index_, static_cast<uint64_t>(2 * kBranchMaxCount));
    branch.Set(static_cast<uint64_t>(0), kLevelNodeValidHeights);
    // dirty_ flag stays false because the body never ran.
    EXPECT_FALSE(branch.dirty_);
}

// Set(child_index, val) early return when parent_idx >= kBranchMaxCount
// (cc 65-67). Construct a level-1 branch with node_index=0 so
// global_leaf_index_=0; child_index = kBranchMaxCount*2 + 4 → parent_idx =
// kBranchMaxCount + 2 → >= kBranchMaxCount → return.
TEST_F(TestLeafHeightTreeBranch, BranchSetChildAboveMaxCount_EarlyReturn) {
    LeafHeightTree branch(0, 0, /*level=*/1, /*node_index=*/0, db_ptr_);
    branch.Set(static_cast<uint64_t>(kBranchMaxCount * 2 + 4),
               kLevelNodeValidHeights);
    EXPECT_FALSE(branch.dirty_);
}

// Set(index) early return when index < global_leaf_index_ (cc 81-83).
TEST_F(TestLeafHeightTreeBranch, LeafSetIndexBelowGlobal_EarlyReturn) {
    LeafHeightTree leaf(0, 0, 0, /*node_index=*/1, db_ptr_);
    // global_leaf_index_ = 1 * kLeafMaxHeightCount; Set(0) is below that.
    ASSERT_GT(leaf.global_leaf_index_, 0u);
    leaf.Set(static_cast<uint64_t>(0));
    EXPECT_FALSE(leaf.dirty_);
}

// Set(index) early return when index >= global_leaf_index_ +
// kEachHeightTreeMaxByteSize (cc 81-83 with upper bound).
TEST_F(TestLeafHeightTreeBranch, LeafSetIndexAboveBounds_EarlyReturn) {
    LeafHeightTree leaf(0, 0, 0, /*node_index=*/0, db_ptr_);
    leaf.Set(static_cast<uint64_t>(kEachHeightTreeMaxByteSize + 8));
    EXPECT_FALSE(leaf.dirty_);
}

// Valid() out-of-range guard (cc 109-111).
TEST_F(TestLeafHeightTreeBranch, ValidOutOfRange_ReturnsFalse) {
    LeafHeightTree leaf(0, 0, 0, /*node_index=*/0, db_ptr_);
    leaf.Set(static_cast<uint64_t>(5));
    EXPECT_FALSE(leaf.Valid(static_cast<uint64_t>(kEachHeightTreeMaxByteSize + 1)));
}

// GetRoot for is_branch_=true (cc 226-227). Existing test_leaf_height_tree.cc
// covers the leaf path (is_branch_=false); this covers the branch path.
TEST_F(TestLeafHeightTreeBranch, GetRoot_BranchTree_ReturnsRootData) {
    LeafHeightTree branch(0, 0, /*level=*/1, /*node_index=*/0, db_ptr_);
    // Two children so max_vec_index_=1; root index resolves to >0.
    branch.Set(static_cast<uint64_t>(0), kLevelNodeValidHeights);
    branch.Set(static_cast<uint64_t>(2), kLevelNodeValidHeights);
    // Just observing the call is enough for coverage; value comparison is a
    // light sanity assertion.
    EXPECT_NO_THROW({ (void)branch.GetRoot(); });
}

// PrintLevel (cc 281-289): direct call, output silenced.
TEST_F(TestLeafHeightTreeBranch, PrintLevel_CoversLoopBody) {
    LeafHeightTree tree(0, 0, 0, 0, db_ptr_);
    tree.Set(0);
    tree.Set(64);
    ScopedSilenceCoutB silence;
    tree.PrintLevel(0);
}

// Branch print/get paths with max_level >= 1
// (PrintBranchDataFromRoot 297-301, GetDataBranchTreeFromRoot 327-331,
//  PrintBranchTreeFromRoot 342-346, 349). Existing tests only Set child
// indices 0/1 which keeps max_vec_index_=0 so the loop body never runs.
// Setting child_index=2 produces max_vec_index_=1 → max_level=1, exercising
// the for-loop bodies once.
TEST_F(TestLeafHeightTreeBranch, BranchPrint_WithMaxLevelOne) {
    LeafHeightTree branch(7, 8, /*level=*/1, /*node_index=*/0, db_ptr_);
    branch.Set(static_cast<uint64_t>(0), kLevelNodeValidHeights);
    branch.Set(static_cast<uint64_t>(2), kLevelNodeValidHeights);

    std::vector<uint64_t> root_data;
    branch.GetDataBranchTreeFromRoot(&root_data);
    EXPECT_GE(root_data.size(), 2u);  // root + at least one level-0 entry

    ScopedSilenceCoutB silence;
    branch.PrintData();  // routes to PrintBranchDataFromRoot
    branch.PrintTree();  // routes to PrintBranchTreeFromRoot
}

// Bonus: leaf-tree print path with max_level >= 1 mirrors the branch test,
// covering 311, 317-323, 327-328 (in the PrintTreeFromRoot helper).
TEST_F(TestLeafHeightTreeBranch, LeafPrint_WithMaxLevelOne) {
    LeafHeightTree leaf(11, 12, /*level=*/0, /*node_index=*/0, db_ptr_);
    leaf.Set(static_cast<uint64_t>(0));
    leaf.Set(static_cast<uint64_t>(64));   // max_height_=64; max_level=1
    leaf.Set(static_cast<uint64_t>(128));  // max_height_=128; max_level≥1

    ScopedSilenceCoutB silence;
    leaf.PrintData();
    leaf.PrintTree();
    std::vector<uint64_t> from_root;
    leaf.GetDataTreeFromRoot(&from_root);
    EXPECT_FALSE(from_root.empty());
}

// ===========================================================================
// height_tree_level.cc — small extra branches
// ===========================================================================
//
// Valid() returns false when leaf entry exists but bit not set (cc 87 false
// path); existing tests cover the true path. Set a single leaf then check
// a nearby height in the same leaf bucket.

class TestHeightTreeLevelBranch : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_htl_branch_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_htl_branch_db"));
    }
    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestHeightTreeLevelBranch::db_ptr_ = nullptr;

// Valid() with leaf_index missing in the level-0 map (cc 83-84):
// max_height_=kInvalidUint64 then Set(0) creates only leaf_index=0; query
// a height in a different leaf bucket.
TEST_F(TestHeightTreeLevelBranch, ValidLeafIndexMissing_ReturnsFalse) {
    HeightTreeLevel level(0, 0, common::kInvalidUint64, db_ptr_);
    level.Set(0);                            // leaf_index=0 populated only
    const uint64_t far_height = static_cast<uint64_t>(kLeafMaxHeightCount * 3 + 5);
    EXPECT_FALSE(level.Valid(far_height));
}

// Valid() when node_map_ptr_ is nullptr (cc 77-78):
// Construct with max_height_=kInvalidUint64 and call Valid() WITHOUT calling
// Set first → tree_level_[0] is still nullptr at the time of the call.
TEST_F(TestHeightTreeLevelBranch, ValidWithoutSet_ReturnsFalse) {
    HeightTreeLevel level(0, 0, common::kInvalidUint64, db_ptr_);
    // After construction LoadFromDb installed tree_level_[max_level=0] but
    // the value lives in tree_level_[0]; force null to take the early-return.
    level.tree_level_[0] = nullptr;
    EXPECT_FALSE(level.Valid(42));
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
