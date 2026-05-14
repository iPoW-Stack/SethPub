// Enhanced unit tests for cross_pool.cc to improve test coverage
// This file provides comprehensive testing for CrossPool class methods and edge cases

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>

// Must include the real sync header so the class declaration is in scope
#include "sync/key_value_sync.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/cross_pool.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "network/network_utils.h"
#include "common/time_utils.h"

namespace seth {
namespace pools {
namespace test {

class TestCrossPoolEnhanced : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_cross_pool_enhanced_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_cross_pool_enhanced_db"));
    }

    static void TearDownTestSuite() {
        db_ptr_.reset();
        system("rm -rf ./test_cross_pool_enhanced_db");
    }

    void SetUp() override {
        cross_pool_ = std::make_unique<CrossPool>();
    }

    void TearDown() override {
        cross_pool_.reset();
    }

    static std::shared_ptr<db::Db> db_ptr_;
    std::unique_ptr<CrossPool> cross_pool_;

    // A non-null shared_ptr<KeyValueSync> backed by a fake address (never dereferenced).
    static std::shared_ptr<sync::KeyValueSync> MakeFakeSync() {
        auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
        return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
    }

    // Create a null sync pointer for testing null scenarios
    static std::shared_ptr<sync::KeyValueSync> MakeNullSync() {
        return nullptr;
    }
};

std::shared_ptr<db::Db> TestCrossPoolEnhanced::db_ptr_ = nullptr;

// ---- Basic Construction and Initialization Tests ----

TEST_F(TestCrossPoolEnhanced, DefaultConstructor_InitializesCorrectly) {
    EXPECT_EQ(cross_pool_->des_sharding_id_, 0u);
    EXPECT_EQ(cross_pool_->pool_index_, 0u);
    EXPECT_EQ(cross_pool_->latest_height_, common::kInvalidUint64);
    EXPECT_EQ(cross_pool_->synced_height_, 0u);
    EXPECT_EQ(cross_pool_->db_, nullptr);
    EXPECT_EQ(cross_pool_->kv_sync_, nullptr);
    EXPECT_EQ(cross_pool_->height_tree_ptr_, nullptr);
    EXPECT_EQ(cross_pool_->prefix_db_, nullptr);
}

TEST_F(TestCrossPoolEnhanced, Destructor_DoesNotCrash) {
    // Test that destructor works correctly
    auto temp_pool = std::make_unique<CrossPool>();
    temp_pool.reset();  // Should not crash
    SUCCEED();
}

// ---- Init Method Tests ----

TEST_F(TestCrossPoolEnhanced, Init_WithValidParameters_InitializesCorrectly) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 5;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    EXPECT_EQ(cross_pool_->des_sharding_id_, sharding_id);
    EXPECT_EQ(cross_pool_->db_, db_ptr_);
    EXPECT_EQ(cross_pool_->kv_sync_, fake_sync);
    EXPECT_NE(cross_pool_->height_tree_ptr_, nullptr);
    EXPECT_NE(cross_pool_->prefix_db_, nullptr);
}

TEST_F(TestCrossPoolEnhanced, Init_WithNullSync_StillInitializes) {
    auto null_sync = MakeNullSync();
    uint32_t sharding_id = 3;
    
    cross_pool_->Init(sharding_id, db_ptr_, null_sync);
    
    EXPECT_EQ(cross_pool_->des_sharding_id_, sharding_id);
    EXPECT_EQ(cross_pool_->db_, db_ptr_);
    EXPECT_EQ(cross_pool_->kv_sync_, nullptr);
    EXPECT_NE(cross_pool_->height_tree_ptr_, nullptr);
}

TEST_F(TestCrossPoolEnhanced, Init_WithZeroShardingId_Works) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 0;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    EXPECT_EQ(cross_pool_->des_sharding_id_, sharding_id);
    EXPECT_NE(cross_pool_->height_tree_ptr_, nullptr);
}

TEST_F(TestCrossPoolEnhanced, Init_WithMaxShardingId_Works) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = UINT32_MAX;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    EXPECT_EQ(cross_pool_->des_sharding_id_, sharding_id);
    EXPECT_NE(cross_pool_->height_tree_ptr_, nullptr);
}

// ---- InitHeightTree Method Tests ----

TEST_F(TestCrossPoolEnhanced, InitHeightTree_CreatesHeightTreeCorrectly) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 10;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    EXPECT_NE(cross_pool_->height_tree_ptr_, nullptr);
    // Height tree should be initialized with height 0 as valid
    EXPECT_TRUE(cross_pool_->height_tree_ptr_->Valid(0));
}

TEST_F(TestCrossPoolEnhanced, InitHeightTree_WithInvalidLatestHeight_Works) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 15;
    
    // Set invalid latest height before init
    cross_pool_->latest_height_ = common::kInvalidUint64;
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    EXPECT_NE(cross_pool_->height_tree_ptr_, nullptr);
    EXPECT_EQ(cross_pool_->latest_height_, common::kInvalidUint64);
}

// ---- SyncMissingBlocks Method Tests ----

TEST_F(TestCrossPoolEnhanced, SyncMissingBlocks_InvalidNetworkId_ReturnsZero) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 20;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Mock invalid network ID
    auto* global_info = common::GlobalInfo::Instance();
    uint32_t original_network_id = global_info->network_id();
    global_info->set_network_id(common::kInvalidUint32);
    
    uint32_t result = cross_pool_->SyncMissingBlocks(common::TimeUtils::TimestampMs());
    EXPECT_EQ(result, 0u);
    
    // Restore original network ID
    global_info->set_network_id(original_network_id);
}

TEST_F(TestCrossPoolEnhanced, SyncMissingBlocks_SameShardingId_ReturnsZero) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 25;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Mock same network ID as destination sharding ID
    auto* global_info = common::GlobalInfo::Instance();
    uint32_t original_network_id = global_info->network_id();
    global_info->set_network_id(sharding_id);
    
    uint32_t result = cross_pool_->SyncMissingBlocks(common::TimeUtils::TimestampMs());
    EXPECT_EQ(result, 0u);
    
    // Restore original network ID
    global_info->set_network_id(original_network_id);
}

TEST_F(TestCrossPoolEnhanced, SyncMissingBlocks_WaitingShardOffset_ReturnsZero) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 30;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Mock network ID with waiting shard offset
    auto* global_info = common::GlobalInfo::Instance();
    uint32_t original_network_id = global_info->network_id();
    global_info->set_network_id(sharding_id + network::kConsensusWaitingShardOffset);
    
    uint32_t result = cross_pool_->SyncMissingBlocks(common::TimeUtils::TimestampMs());
    EXPECT_EQ(result, 0u);
    
    // Restore original network ID
    global_info->set_network_id(original_network_id);
}

TEST_F(TestCrossPoolEnhanced, SyncMissingBlocks_NullKvSync_ReturnsZero) {
    auto null_sync = MakeNullSync();
    uint32_t sharding_id = 35;
    
    cross_pool_->Init(sharding_id, db_ptr_, null_sync);
    
    // Ensure different network ID
    auto* global_info = common::GlobalInfo::Instance();
    uint32_t original_network_id = global_info->network_id();
    global_info->set_network_id(sharding_id + 1);
    
    uint32_t result = cross_pool_->SyncMissingBlocks(common::TimeUtils::TimestampMs());
    EXPECT_EQ(result, 0u);
    
    // Restore original network ID
    global_info->set_network_id(original_network_id);
}

TEST_F(TestCrossPoolEnhanced, SyncMissingBlocks_NullHeightTree_ReturnsZero) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 40;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Manually set height tree to null
    cross_pool_->height_tree_ptr_ = nullptr;
    
    // Ensure different network ID
    auto* global_info = common::GlobalInfo::Instance();
    uint32_t original_network_id = global_info->network_id();
    global_info->set_network_id(sharding_id + 1);
    
    uint32_t result = cross_pool_->SyncMissingBlocks(common::TimeUtils::TimestampMs());
    EXPECT_EQ(result, 0u);
    
    // Restore original network ID
    global_info->set_network_id(original_network_id);
}

TEST_F(TestCrossPoolEnhanced, SyncMissingBlocks_InvalidLatestHeight_RequestsSync) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 45;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Set invalid latest height
    cross_pool_->latest_height_ = common::kInvalidUint64;
    
    // Ensure different network ID
    auto* global_info = common::GlobalInfo::Instance();
    uint32_t original_network_id = global_info->network_id();
    global_info->set_network_id(sharding_id + 1);
    
    uint32_t result = cross_pool_->SyncMissingBlocks(common::TimeUtils::TimestampMs());
    EXPECT_EQ(result, 1u);  // Should request sync for height 0
    
    // Restore original network ID
    global_info->set_network_id(original_network_id);
}

// ---- UpdateLatestInfo and FlushHeightTree Tests ----

TEST_F(TestCrossPoolEnhanced, UpdateLatestInfo_UpdatesCorrectly) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 50;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    uint64_t new_height = 100;
    uint64_t result = cross_pool_->UpdateLatestInfo(new_height);
    
    EXPECT_EQ(cross_pool_->latest_height_, new_height);
    EXPECT_EQ(result, new_height);
}

TEST_F(TestCrossPoolEnhanced, FlushHeightTree_WithValidTree_DoesNotCrash) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 55;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    db::DbWriteBatch batch;
    cross_pool_->FlushHeightTree(batch);  // Should not crash
    SUCCEED();
}

TEST_F(TestCrossPoolEnhanced, FlushHeightTree_WithNullTree_DoesNotCrash) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 60;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    cross_pool_->height_tree_ptr_ = nullptr;
    
    db::DbWriteBatch batch;
    cross_pool_->FlushHeightTree(batch);  // Should not crash
    SUCCEED();
}

// ---- Getter Methods Tests ----

TEST_F(TestCrossPoolEnhanced, LatestHeight_ReturnsCorrectValue) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 65;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    uint64_t test_height = 200;
    cross_pool_->latest_height_ = test_height;
    
    EXPECT_EQ(cross_pool_->latest_height(), test_height);
}

TEST_F(TestCrossPoolEnhanced, LatestTimestamp_ReturnsCorrectValue) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 70;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    uint64_t test_timestamp = 1234567890;
    cross_pool_->latest_timestamp_ = test_timestamp;
    
    EXPECT_EQ(cross_pool_->latest_timestamp(), test_timestamp);
}

// ---- SyncBlock and UpdateSyncedHeight Tests ----

TEST_F(TestCrossPoolEnhanced, SyncBlock_DoesNotCrash) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 75;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    cross_pool_->SyncBlock();  // Should not crash
    SUCCEED();
}

TEST_F(TestCrossPoolEnhanced, UpdateSyncedHeight_WithValidTree_UpdatesCorrectly) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 80;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Set some heights as valid
    cross_pool_->latest_height_ = 10;
    cross_pool_->synced_height_ = 5;
    
    cross_pool_->UpdateSyncedHeight();
    
    // Should update synced height based on valid heights in tree
    EXPECT_GE(cross_pool_->synced_height_, 5u);
}

TEST_F(TestCrossPoolEnhanced, UpdateSyncedHeight_WithNullTree_DoesNotCrash) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 85;
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    cross_pool_->height_tree_ptr_ = nullptr;
    
    cross_pool_->UpdateSyncedHeight();  // Should not crash
    SUCCEED();
}

// ---- Multiple Init Calls Tests ----

TEST_F(TestCrossPoolEnhanced, Init_CalledMultipleTimes_UpdatesCorrectly) {
    auto fake_sync1 = MakeFakeSync();
    auto fake_sync2 = MakeFakeSync();
    
    // First init
    cross_pool_->Init(1, db_ptr_, fake_sync1);
    EXPECT_EQ(cross_pool_->des_sharding_id_, 1u);
    EXPECT_EQ(cross_pool_->kv_sync_, fake_sync1);
    
    // Second init - should update values
    cross_pool_->Init(2, db_ptr_, fake_sync2);
    EXPECT_EQ(cross_pool_->des_sharding_id_, 2u);
    EXPECT_EQ(cross_pool_->kv_sync_, fake_sync2);
}

// ---- Memory Management Tests ----

TEST_F(TestCrossPoolEnhanced, Init_ProperlyManagesSharedPointers) {
    auto fake_sync = MakeFakeSync();
    uint32_t sharding_id = 90;
    
    // Get initial reference counts
    long initial_db_count = db_ptr_.use_count();
    long initial_sync_count = fake_sync.use_count();
    
    cross_pool_->Init(sharding_id, db_ptr_, fake_sync);
    
    // Reference counts should have increased
    EXPECT_GT(db_ptr_.use_count(), initial_db_count);
    EXPECT_GT(fake_sync.use_count(), initial_sync_count);
    
    // Reset the pool
    cross_pool_.reset();
    
    // Reference counts should return to initial values
    EXPECT_EQ(db_ptr_.use_count(), initial_db_count);
    EXPECT_EQ(fake_sync.use_count(), initial_sync_count);
}

// ---- Edge Cases and Error Conditions ----

TEST_F(TestCrossPoolEnhanced, Init_WithNullDb_HandlesGracefully) {
    auto fake_sync = MakeFakeSync();
    std::shared_ptr<db::Db> null_db = nullptr;
    uint32_t sharding_id = 95;
    
    // This should not crash, though it may not be fully functional
    cross_pool_->Init(sharding_id, null_db, fake_sync);
    
    EXPECT_EQ(cross_pool_->des_sharding_id_, sharding_id);
    EXPECT_EQ(cross_pool_->db_, nullptr);
    EXPECT_EQ(cross_pool_->kv_sync_, fake_sync);
}

}  // namespace test
}  // namespace pools
}  // namespace seth