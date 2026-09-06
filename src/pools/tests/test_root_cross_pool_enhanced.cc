// Enhanced unit tests for root_cross_pool.cc to improve test coverage
// This file provides comprehensive testing for RootCrossPool class methods and edge cases

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>

// Must include the real sync header so the class declaration is in scope
#include "sync/key_value_sync.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/root_cross_pool.h"
#include "pools/cross_pool.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "network/network_utils.h"

namespace shardora {
namespace pools {
namespace test {

class TestRootCrossPoolEnhanced : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_root_cross_pool_enhanced_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_root_cross_pool_enhanced_db"));
    }

    static void TearDownTestSuite() {
        db_ptr_.reset();
        system("rm -rf ./test_root_cross_pool_enhanced_db");
    }

    void SetUp() override {
        root_pool_ = std::make_unique<RootCrossPool>();
    }

    void TearDown() override {
        root_pool_.reset();
    }

    static std::shared_ptr<db::Db> db_ptr_;
    std::unique_ptr<RootCrossPool> root_pool_;

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

std::shared_ptr<db::Db> TestRootCrossPoolEnhanced::db_ptr_ = nullptr;

// ---- Basic Construction and Initialization Tests ----

TEST_F(TestRootCrossPoolEnhanced, DefaultConstructor_SetsCorrectShardingId) {
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);
    EXPECT_EQ(root_pool_->pool_index_, 0u);  // Default value
    EXPECT_EQ(root_pool_->latest_height_, common::kInvalidUint64);
    EXPECT_EQ(root_pool_->synced_height_, 0u);
    EXPECT_EQ(root_pool_->db_, nullptr);
    EXPECT_EQ(root_pool_->kv_sync_, nullptr);
    EXPECT_EQ(root_pool_->height_tree_ptr_, nullptr);
}

TEST_F(TestRootCrossPoolEnhanced, Destructor_DoesNotCrash) {
    // Test that destructor works correctly
    auto temp_pool = std::make_unique<RootCrossPool>();
    temp_pool.reset();  // Should not crash
    SUCCEED();
}

// ---- Init Method Tests ----

TEST_F(TestRootCrossPoolEnhanced, Init_WithValidParameters_InitializesCorrectly) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 5;
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    EXPECT_EQ(root_pool_->pool_index_, pool_idx);
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);
    EXPECT_EQ(root_pool_->db_, db_ptr_);
    EXPECT_EQ(root_pool_->kv_sync_, fake_sync);
    EXPECT_NE(root_pool_->height_tree_ptr_, nullptr);
    EXPECT_NE(root_pool_->prefix_db_, nullptr);
}

TEST_F(TestRootCrossPoolEnhanced, Init_WithNullSync_StillInitializes) {
    auto null_sync = MakeNullSync();
    uint32_t pool_idx = 3;
    
    root_pool_->Init(pool_idx, db_ptr_, null_sync);
    
    EXPECT_EQ(root_pool_->pool_index_, pool_idx);
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);
    EXPECT_EQ(root_pool_->db_, db_ptr_);
    EXPECT_EQ(root_pool_->kv_sync_, nullptr);
    EXPECT_NE(root_pool_->height_tree_ptr_, nullptr);
}

TEST_F(TestRootCrossPoolEnhanced, Init_WithZeroPoolIndex_Works) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 0;
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    EXPECT_EQ(root_pool_->pool_index_, pool_idx);
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);
}

TEST_F(TestRootCrossPoolEnhanced, Init_WithMaxPoolIndex_Works) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = UINT32_MAX;
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    EXPECT_EQ(root_pool_->pool_index_, pool_idx);
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);
}

// ---- Multiple Init Calls Tests ----

TEST_F(TestRootCrossPoolEnhanced, Init_CalledMultipleTimes_UpdatesCorrectly) {
    auto fake_sync1 = MakeFakeSync();
    auto fake_sync2 = MakeFakeSync();
    
    // First init
    root_pool_->Init(1, db_ptr_, fake_sync1);
    EXPECT_EQ(root_pool_->pool_index_, 1u);
    EXPECT_EQ(root_pool_->kv_sync_, fake_sync1);
    
    // Second init - should update values
    root_pool_->Init(2, db_ptr_, fake_sync2);
    EXPECT_EQ(root_pool_->pool_index_, 2u);
    EXPECT_EQ(root_pool_->kv_sync_, fake_sync2);
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);  // Should remain constant
}

// ---- Inheritance Behavior Tests ----

TEST_F(TestRootCrossPoolEnhanced, Init_CallsParentClassInit) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 7;
    
    // Before init, parent class members should be uninitialized
    EXPECT_EQ(root_pool_->db_, nullptr);
    EXPECT_EQ(root_pool_->prefix_db_, nullptr);
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    // After init, parent class members should be initialized
    EXPECT_EQ(root_pool_->db_, db_ptr_);
    EXPECT_NE(root_pool_->prefix_db_, nullptr);
    EXPECT_NE(root_pool_->height_tree_ptr_, nullptr);
}

// ---- Edge Cases and Error Conditions ----

TEST_F(TestRootCrossPoolEnhanced, Init_WithNullDb_HandlesGracefully) {
    auto fake_sync = MakeFakeSync();
    std::shared_ptr<db::Db> null_db = nullptr;
    uint32_t pool_idx = 1;
    
    // This should not crash, though it may not be fully functional
    root_pool_->Init(pool_idx, null_db, fake_sync);
    
    EXPECT_EQ(root_pool_->pool_index_, pool_idx);
    EXPECT_EQ(root_pool_->db_, nullptr);
    EXPECT_EQ(root_pool_->kv_sync_, fake_sync);
}

// ---- State Consistency Tests ----

TEST_F(TestRootCrossPoolEnhanced, Init_MaintainsStateConsistency) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 10;
    
    // Store initial state
    uint32_t initial_sharding_id = root_pool_->des_sharding_id_;
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    // Verify that sharding ID is preserved (should always be root congress network)
    EXPECT_EQ(root_pool_->des_sharding_id_, initial_sharding_id);
    EXPECT_EQ(root_pool_->des_sharding_id_, network::kRootCongressNetworkId);
    
    // Verify that pool index is updated correctly
    EXPECT_EQ(root_pool_->pool_index_, pool_idx);
}

// ---- Polymorphic Behavior Tests ----

TEST_F(TestRootCrossPoolEnhanced, PolymorphicUsage_WorksCorrectly) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 15;
    
    // Use RootCrossPool through CrossPool pointer
    std::unique_ptr<CrossPool> base_ptr = std::make_unique<RootCrossPool>();
    
    // Should be able to call Init through base pointer
    base_ptr->Init(network::kRootCongressNetworkId, db_ptr_, fake_sync);
    
    // Verify initialization worked
    EXPECT_EQ(base_ptr->des_sharding_id_, network::kRootCongressNetworkId);
    EXPECT_NE(base_ptr->height_tree_ptr_, nullptr);
}

// ---- Memory Management Tests ----

TEST_F(TestRootCrossPoolEnhanced, Init_ProperlyManagesSharedPointers) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 20;
    
    // Get initial reference counts
    long initial_db_count = db_ptr_.use_count();
    long initial_sync_count = fake_sync.use_count();
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    // Reference counts should have increased
    EXPECT_GT(db_ptr_.use_count(), initial_db_count);
    EXPECT_GT(fake_sync.use_count(), initial_sync_count);
    
    // Reset the pool
    root_pool_.reset();
    
    // Reference counts should return to initial values
    EXPECT_EQ(db_ptr_.use_count(), initial_db_count);
    EXPECT_EQ(fake_sync.use_count(), initial_sync_count);
}

// ---- Functional Integration Tests ----

TEST_F(TestRootCrossPoolEnhanced, Init_EnablesBasicFunctionality) {
    auto fake_sync = MakeFakeSync();
    uint32_t pool_idx = 25;
    
    root_pool_->Init(pool_idx, db_ptr_, fake_sync);
    
    // Should be able to access basic functionality inherited from CrossPool
    EXPECT_EQ(root_pool_->latest_height(), common::kInvalidUint64);
    EXPECT_GE(root_pool_->synced_height_, 0u);
    
    // Height tree should be functional
    EXPECT_NE(root_pool_->height_tree_ptr_, nullptr);
    if (root_pool_->height_tree_ptr_) {
        EXPECT_TRUE(root_pool_->height_tree_ptr_->Valid(0));
    }
}

}  // namespace test
}  // namespace pools
}  // namespace shardora