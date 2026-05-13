// Branch-coverage tests for ToTxsPools (to_txs_pools.cc).
//
// to_txs_pools.o's only non-virtual external reference outside the linked
// libraries is AccountManager::GetAccountInfo.  The stub lives in
// test_pools_stubs.cc — do not duplicate it here.  pools_mgr_ is kept null
// so that LoadLatestHeights() is skipped (its pools_mgr_->latest_height()
// call would dereference a TxPool array we'd have to fully initialise).

#include <gtest/gtest.h>

#include <memory>

// Include AccountManager header so the class is declared in this TU.
#include "block/account_manager.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/to_txs_pools.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "network/network_utils.h"
#include "pools/tx_pool_manager.h"

namespace seth {
namespace pools {
namespace test {

class TestToTxsPools : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_to_txs_pools_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_to_txs_pools_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;

    // Construct a ToTxsPools with null pools_mgr and acc_mgr so that
    // LoadLatestHeights() is skipped.
    ToTxsPools MakePool() {
        std::shared_ptr<pools::TxPoolManager> null_mgr;
        std::shared_ptr<block::AccountManager> null_acc;
        return ToTxsPools(db_ptr_, "", 0, null_mgr, null_acc);
    }
};

std::shared_ptr<db::Db> TestToTxsPools::db_ptr_ = nullptr;

// ---- Constructor: null pools_mgr → LoadLatestHeights skipped ----

TEST_F(TestToTxsPools, Constructor_NullPoolsMgr_SkipsLoadLatestHeights) {
    auto pool = MakePool();
    // prev_to_heights_ should still be null (LoadLatestHeights was not called)
    EXPECT_EQ(pool.prev_to_heights_, nullptr);
}

TEST_F(TestToTxsPools, Constructor_NonNullPoolsMgr_InvalidNetwork_LoadLatestReturnsImmediately) {
    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    auto stub_mgr = std::shared_ptr<TxPoolManager>(
        reinterpret_cast<TxPoolManager*>(0xA0uLL), [](TxPoolManager*) {});
    std::shared_ptr<block::AccountManager> null_acc;
    ToTxsPools pool(db_ptr_, "lid", 0u, stub_mgr, null_acc);
    (void)pool;
    common::GlobalInfo::Instance()->set_network_id(prev);
}

TEST_F(TestToTxsPools, Constructor_NonNullPoolsMgr_ValidNetwork_GetLatestHeightsMissing_ReturnsEarly) {
    const uint32_t prev = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    auto stub_mgr = std::shared_ptr<TxPoolManager>(
        reinterpret_cast<TxPoolManager*>(0xA1uLL), [](TxPoolManager*) {});
    std::shared_ptr<block::AccountManager> null_acc;
    ToTxsPools pool(db_ptr_, "lid2", 3u, stub_mgr, null_acc);
    (void)pool;
    common::GlobalInfo::Instance()->set_network_id(prev);
}

// ---- LeaderCreateToHeights: prev_to_heights_ == nullptr → kPoolsError ----

TEST_F(TestToTxsPools, LeaderCreateToHeights_NullPrevHeights_ReturnsError) {
    auto pool = MakePool();
    // prev_to_heights_ is null (unchanged from MakePool)
    pools::protobuf::ShardToTxItem out;
    EXPECT_EQ(pool.LeaderCreateToHeights(out), kPoolsError);
}

// ---- LeaderCreateToHeights: in-flight tx still within 30 s timeout → kPoolsError ----

TEST_F(TestToTxsPools, LeaderCreateToHeights_InFlightWithinTimeout_ReturnsError) {
    auto pool = MakePool();
    // Set prev_to_heights_ so we pass the null check
    auto prev = std::make_shared<pools::protobuf::ShardToTxItem>();
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        prev->add_heights(0);
    }
    pool.prev_to_heights_ = prev;
    // Simulate a recent in-flight leader_to_heights_ (set just now)
    pool.leader_to_heights_.store(
        std::make_shared<pools::protobuf::ShardToTxItem>());
    pool.leader_to_heights_set_tm_ = common::TimeUtils::TimestampMs();

    pools::protobuf::ShardToTxItem out;
    EXPECT_EQ(pool.LeaderCreateToHeights(out), kPoolsError);
}

// ---- LeaderCreateToHeights: no valid heights → kPoolsError (valid=false) ----
// pool_consensus_heihgts_[i] == 0 and prev heights == 0: the while loop
// condition (cons_height > 0) is false for every pool, valid stays false.

TEST_F(TestToTxsPools, LeaderCreateToHeights_NoValidHeights_ReturnsError) {
    auto pool = MakePool();
    // Provide prev_to_heights_ with kInvalidPoolIndex zeros
    auto prev = std::make_shared<pools::protobuf::ShardToTxItem>();
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        prev->add_heights(0);
    }
    pool.prev_to_heights_ = prev;
    // pool_consensus_heihgts_ default is 0 for all pools — loop body never entered

    pools::protobuf::ShardToTxItem out;
    EXPECT_EQ(pool.LeaderCreateToHeights(out), kPoolsError);
}

// ---- LeaderCreateToHeights: valid height in pool 0 → kPoolsSuccess ----
// pool_consensus_heihgts_[0] = 1, valided_heights_[0] contains 1,
// prev_to_heights_.heights(0) = 0 → valid=true and new height (1) > prev (0).

TEST_F(TestToTxsPools, LeaderCreateToHeights_ValidHeight_ReturnsSuccess) {
    auto pool = MakePool();
    auto prev = std::make_shared<pools::protobuf::ShardToTxItem>();
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        prev->add_heights(0);
    }
    pool.prev_to_heights_ = prev;
    // Make pool 0 have a validated height at 1
    pool.pool_consensus_heihgts_[0] = 1;
    pool.valided_heights_[0].insert(1);

    pools::protobuf::ShardToTxItem out;
    EXPECT_EQ(pool.LeaderCreateToHeights(out), kPoolsSuccess);
    EXPECT_EQ(out.heights(0), 1u);
}

// ---- LoadLatestHeights: kInvalidUint32 network_id → early return ----

TEST_F(TestToTxsPools, LoadLatestHeights_InvalidNetworkId_EarlyReturn) {
    auto pool = MakePool();
    auto prev_net = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);
    // prev_to_heights_ stays null after LoadLatestHeights returns immediately
    pool.LoadLatestHeights();
    EXPECT_EQ(pool.prev_to_heights_, nullptr);
    common::GlobalInfo::Instance()->set_network_id(prev_net);
}

// ---- LoadLatestHeights: GetLatestToTxsHeights fails → early return ----
// With a valid network_id but empty db, GetLatestToTxsHeights returns false.

TEST_F(TestToTxsPools, LoadLatestHeights_DbMiss_EarlyReturn) {
    auto pool = MakePool();
    auto prev_net = common::GlobalInfo::Instance()->network_id();
    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    pool.LoadLatestHeights();
    // No heights stored in db → prev_to_heights_ stays null
    EXPECT_EQ(pool.prev_to_heights_, nullptr);
    common::GlobalInfo::Instance()->set_network_id(prev_net);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
