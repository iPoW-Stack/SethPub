// Branch-coverage tests for TxPool inline methods defined in tx_pool.h.
//
// Only the inline functions are exercised; Init() is never called so the
// heavy dependency chain (PrefixDb, Security, KeyValueSync) is never
// dereferenced.  The linker stub below satisfies tx_pool.o's sole
// non-virtual external reference (KeyValueSync::AddSyncHeight).

#include <gtest/gtest.h>

#include <memory>

#include "sync/key_value_sync.h"

// ---- Linker stub ----
namespace seth {
namespace sync {
void KeyValueSync::AddSyncHeight(uint32_t, uint32_t, uint64_t, uint32_t) {}
}  // namespace sync
}  // namespace seth
// ---- end stub ----

#define private public
#define protected public
#include "db/db.h"
#include "pools/tx_pool.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "network/network_utils.h"

namespace seth {
namespace pools {
namespace test {

class TestTxPoolInline : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_tx_pool_inline_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_tx_pool_inline_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestTxPoolInline::db_ptr_ = nullptr;

// ---- PoolChainIsFull ----

// Branch: latest_height_ < height → false
TEST_F(TestTxPoolInline, PoolChainIsFull_HeightNotReached_ReturnsFalse) {
    TxPool pool;
    pool.latest_height_ = 5;
    pool.has_missing_height_ = false;
    EXPECT_FALSE(pool.PoolChainIsFull(10));
}

// Branch: latest_height_ >= height, has_missing_height_ = true → false
TEST_F(TestTxPoolInline, PoolChainIsFull_HasMissingHeight_ReturnsFalse) {
    TxPool pool;
    pool.latest_height_ = 10;
    pool.has_missing_height_ = true;
    EXPECT_FALSE(pool.PoolChainIsFull(10));
}

// Branch: latest_height_ >= height, has_missing_height_ = false → true
TEST_F(TestTxPoolInline, PoolChainIsFull_Complete_ReturnsTrue) {
    TxPool pool;
    pool.latest_height_ = 10;
    pool.has_missing_height_ = false;
    EXPECT_TRUE(pool.PoolChainIsFull(10));
}

// ---- OnNewElectBlock ----

// Branch: !IsSameToLocalShard → early return, latest_elect_height_ unchanged
TEST_F(TestTxPoolInline, OnNewElectBlock_DifferentShard_NoUpdate) {
    TxPool pool;
    pool.latest_elect_height_ = 0;
    auto prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    // Pass a different shard so IsSameToLocalShard returns false
    pool.OnNewElectBlock(network::kConsensusShardBeginNetworkId + 1, 100);
    EXPECT_EQ(pool.latest_elect_height_.load(), 0u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: same shard AND elect_height > latest_elect_height_ → updates
TEST_F(TestTxPoolInline, OnNewElectBlock_SameShard_HigherHeight_Updates) {
    TxPool pool;
    pool.latest_elect_height_ = 5;
    auto prev = common::GlobalInfo::Instance()->network_id();
    constexpr uint32_t kShard = network::kConsensusShardBeginNetworkId;
    common::GlobalInfo::Instance()->set_network_id(kShard);
    pool.OnNewElectBlock(kShard, 10);
    EXPECT_EQ(pool.latest_elect_height_.load(), 10u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// Branch: same shard BUT elect_height <= latest_elect_height_ → no update
TEST_F(TestTxPoolInline, OnNewElectBlock_SameShard_LowerHeight_NoUpdate) {
    TxPool pool;
    pool.latest_elect_height_ = 20;
    auto prev = common::GlobalInfo::Instance()->network_id();
    constexpr uint32_t kShard = network::kConsensusShardBeginNetworkId;
    common::GlobalInfo::Instance()->set_network_id(kShard);
    pool.OnNewElectBlock(kShard, 10);
    EXPECT_EQ(pool.latest_elect_height_.load(), 20u);
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---- NewTxValid ----

// Branch: addr not in add_addr_nonce_map_ → true
TEST_F(TestTxPoolInline, NewTxValid_UnknownAddr_ReturnsTrue) {
    TxPool pool;
    EXPECT_TRUE(pool.NewTxValid("unknown_addr", 100));
}

// Branch: over_nonce >= nonce → false
TEST_F(TestTxPoolInline, NewTxValid_OverNonceGe_ReturnsFalse) {
    TxPool pool;
    pool.add_addr_nonce_map_.Put("addr_a", 10);
    EXPECT_FALSE(pool.NewTxValid("addr_a", 5));   // 10 >= 5 → false
    EXPECT_FALSE(pool.NewTxValid("addr_a", 10));  // 10 >= 10 → false
}

// Branch: (over_nonce + 4*kMaxTxCount) <= nonce → false
TEST_F(TestTxPoolInline, NewTxValid_NonceWayAhead_ReturnsFalse) {
    TxPool pool;
    pool.add_addr_nonce_map_.Put("addr_b", 0);
    // 4 * kMaxTxCount(2048) = 8192; 0 + 8192 <= 8192 → false
    EXPECT_FALSE(pool.NewTxValid("addr_b", 8192));
}

// Branch: addr in map, valid nonce range → true
TEST_F(TestTxPoolInline, NewTxValid_ValidNonce_ReturnsTrue) {
    TxPool pool;
    pool.add_addr_nonce_map_.Put("addr_c", 0);
    // 0 >= 100 false; 0+8192 <= 100 false → true
    EXPECT_TRUE(pool.NewTxValid("addr_c", 100));
}

// ---- all_tx_size ----

TEST_F(TestTxPoolInline, AllTxSize_EmptyPool_ReturnsZero) {
    TxPool pool;
    EXPECT_EQ(pool.all_tx_size(), 0u);
}

// ---- FlushHeightTree ----

// Branch: height_tree_ptr_ == nullptr → no-op
TEST_F(TestTxPoolInline, FlushHeightTree_NullTree_NoOp) {
    TxPool pool;
    db::DbWriteBatch batch;
    pool.FlushHeightTree(batch);
}

// Branch: tree present, all heights set → invalid_heights empty → has_missing_height_=false
TEST_F(TestTxPoolInline, FlushHeightTree_AllPresent_ClearsMissingFlag) {
    TxPool pool;
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    pool.height_tree_ptr_->Set(0);
    pool.latest_height_ = 0;
    pool.has_missing_height_ = true;
    db::DbWriteBatch batch;
    pool.FlushHeightTree(batch);
    EXPECT_FALSE(pool.has_missing_height_.load());
}

// Branch: tree present, height missing → invalid_heights non-empty and [0]<=latest_height_
//         → has_missing_height_=true
// A freshly-constructed tree (nothing Set) returns {0} from GetMissingHeights.
TEST_F(TestTxPoolInline, FlushHeightTree_MissingHeight_SetsMissingFlag) {
    TxPool pool;
    pool.height_tree_ptr_ = std::make_shared<HeightTreeLevel>(
        network::kConsensusShardBeginNetworkId, 0, common::kInvalidUint64, db_ptr_);
    // Do NOT call Set: max_height_ stays kInvalidUint64 → GetMissingHeights returns {0}
    pool.latest_height_ = 5;  // 0 <= 5 → sets has_missing_height_=true
    pool.has_missing_height_ = false;
    db::DbWriteBatch batch;
    pool.FlushHeightTree(batch);
    EXPECT_TRUE(pool.has_missing_height_.load());
}

// ---- latest_height() getter ----

// Branch: latest_height_ already set (non-kInvalidUint64) → returns value directly
TEST_F(TestTxPoolInline, LatestHeight_PreSet_ReturnsValue) {
    TxPool pool;
    pool.latest_height_ = 42;
    EXPECT_EQ(pool.latest_height(), 42u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
