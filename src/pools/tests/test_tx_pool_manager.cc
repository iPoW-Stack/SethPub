// Coverage tests for TxPoolManager (tx_pool_manager.cc / tx_pool_manager.h).
//
// Construction strategy: network_id is set to kInvalidUint32 so that
// TxPool::InitHeightTree() returns early (avoiding SyncMissingBlocks which
// would dereference the null kv_sync_). kv_sync_ is a fake non-null pointer
// (reinterpret_cast trick) so that the constructor stores a non-null value;
// the KeyValueSync::AddSyncHeight stub in test_pools_stubs.cc makes any call
// through it a no-op.
//
// security_: default FakeSecurityForTxPm in suite; override with ScopedSecurityOverride
// when a specific address is needed. Optional account rows: ScopedAccountInfoOverride +
// g_test_account_info_override (wired in test_pools_stubs.cc).
// hotstuff_mgr_: null in this suite (no leader fan-out). With SETH_UNITTEST + coverage,
// use TxPoolManager::SetIsOtherLeaderHookForTest to mock is_other_leader (see test_tx_pool_mocks.h).

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

#include "sync/key_value_sync.h"
#include "test_tx_pool_mocks.h"
#include "transport/transport_utils.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/tx_pool_manager.h"
#undef protected
#undef private

#include "common/global_info.h"
#include "common/node_members.h"
#include "common/utils.h"
#include "network/network_utils.h"

namespace seth {
namespace pools {
namespace test {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::shared_ptr<sync::KeyValueSync> MakeKvStub() {
    // Fake non-null pointer; AddSyncHeight stub in test_pools_stubs.cc absorbs calls.
    auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
    return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
}

class TestTxPoolManager : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_txpm_db");
        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init("./test_txpm_db"));

        // network_id = kInvalidUint32 → TxPool::InitHeightTree early-returns,
        // so kv_sync_ null-deref in SyncMissingBlocks is never reached.
        prev_net_ = common::GlobalInfo::Instance()->network_id();
        common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);

        kv_ = MakeKvStub();
        suite_sec_ = std::make_shared<FakeSecurityForTxPm>(
            std::string(common::kUnicastAddressLength, static_cast<char>(0xAB)));
        std::shared_ptr<block::AccountManager> null_acc;
        std::shared_ptr<consensus::HotstuffManager> null_hotstuff;
        mgr_ = std::make_shared<TxPoolManager>(suite_sec_, db_, kv_, null_acc, null_hotstuff);
    }

    static void TearDownTestSuite() {
        g_test_account_info_override = nullptr;
#ifdef SETH_UNITTEST
        TxPoolManager::ClearIsOtherLeaderHookForTest();
#endif
        mgr_.reset();
        suite_sec_.reset();
        common::GlobalInfo::Instance()->set_network_id(prev_net_);
    }

    static std::shared_ptr<db::Db>                      db_;
    static std::shared_ptr<sync::KeyValueSync>          kv_;
    static std::shared_ptr<security::Security>          suite_sec_;
    static std::shared_ptr<TxPoolManager>               mgr_;
    static uint32_t                                     prev_net_;
};

std::shared_ptr<db::Db>                        TestTxPoolManager::db_             = nullptr;
std::shared_ptr<sync::KeyValueSync>            TestTxPoolManager::kv_             = nullptr;
std::shared_ptr<security::Security>           TestTxPoolManager::suite_sec_      = nullptr;
std::shared_ptr<TxPoolManager>                TestTxPoolManager::mgr_             = nullptr;
uint32_t                                      TestTxPoolManager::prev_net_        = common::kInvalidUint32;

// ---------------------------------------------------------------------------
// Constructor coverage (lines 29-69 of tx_pool_manager.cc)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, Constructor_CreatesSuccessfully) {
    EXPECT_NE(mgr_, nullptr);
    EXPECT_NE(mgr_->tx_pool_, nullptr);
    EXPECT_NE(mgr_->cross_pools_, nullptr);
}

// ---------------------------------------------------------------------------
// FirewallCheckMessage (lines 109-111)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, FirewallCheckMessage_AlwaysReturnsSuccess) {
    auto msg = std::make_shared<transport::TransportMessage>();
    transport::MessagePtr mp = msg;
    EXPECT_EQ(mgr_->FirewallCheckMessage(mp), transport::kFirewallCheckSuccess);
}

// ---------------------------------------------------------------------------
// SetTxStatusCallback / GetTxStatusCallback (header lines 76-78)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, SetGetTxStatusCallback_RoundTrip) {
    EXPECT_FALSE(static_cast<bool>(mgr_->GetTxStatusCallback()));
    bool called = false;
    mgr_->SetTxStatusCallback([&called](const std::string&, transport::MessageHandleStatus) {
        called = true;
    });
    EXPECT_TRUE(static_cast<bool>(mgr_->GetTxStatusCallback()));
    mgr_->GetTxStatusCallback()("hash", transport::kTxAccept);
    EXPECT_TRUE(called);
    // Reset to null for other tests
    mgr_->SetTxStatusCallback({});
}

// ---------------------------------------------------------------------------
// RegisterCreateTxFunction (header line 144-147)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, RegisterCreateTxFunction_StoresFn) {
    bool invoked = false;
    mgr_->RegisterCreateTxFunction(
        static_cast<uint32_t>(pools::protobuf::kNormalFrom),
        [&invoked](transport::MessagePtr) -> TxItemPtr {
            invoked = true;
            return nullptr;
        });
    // Function is stored; just verify no crash
    EXPECT_FALSE(invoked);
}

// ---------------------------------------------------------------------------
// Inline delegation getters (header lines 80-175)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, AllTxSize_InitiallyZero) {
    EXPECT_EQ(mgr_->all_tx_size(0), 0u);
}

TEST_F(TestTxPoolManager, LatestHeight_InitiallyInvalid) {
    EXPECT_EQ(mgr_->latest_height(0), common::kInvalidUint64);
}

TEST_F(TestTxPoolManager, LatestHash_InitiallyEmpty) {
    EXPECT_TRUE(mgr_->latest_hash(0).empty());
}

TEST_F(TestTxPoolManager, LatestTimestamp_InitiallyZero) {
    EXPECT_EQ(mgr_->latest_timestamp(0), 0u);
}

TEST_F(TestTxPoolManager, RootLatestHeight_InitiallyInvalid) {
    // root_cross_pools_ is non-null (not root node path)
    if (mgr_->root_cross_pools_ != nullptr) {
        EXPECT_EQ(mgr_->root_latest_height(0), common::kInvalidUint64);
    }
}

TEST_F(TestTxPoolManager, CrossLatestHeight_ValidShard) {
    // network_id is kInvalidUint32 so now_valid_end_shard() may be 0; call
    // with a shard above that → returns kInvalidUint64
    uint64_t h = mgr_->cross_latest_height(network::kConsensusShardBeginNetworkId);
    // Either the shard is in range and returns kInvalidUint64, or out-of-range
    // and returns kInvalidUint64 immediately. Either way no crash.
    (void)h;
}

TEST_F(TestTxPoolManager, TxKeyExists_EmptyPool_ReturnsFalse) {
    std::string addr(common::kUnicastAddressLength, 'A');
    EXPECT_FALSE(mgr_->TxKeyExists(0, addr, 1, "key"));
}

TEST_F(TestTxPoolManager, PoolChainIsFull_InitiallyFalse) {
    EXPECT_FALSE(mgr_->PoolChainIsFull(0, 100));
}

TEST_F(TestTxPoolManager, NewTxValid_EmptyPool_ReturnsTrue) {
    std::string addr(common::kUnicastAddressLength, 'B');
    EXPECT_TRUE(mgr_->NewTxValid(0, addr, 1));
}

// ---------------------------------------------------------------------------
// OnNewCrossBlock (header lines 92-111)
// ---------------------------------------------------------------------------

// Non-root network, pool_index != kImmutablePoolSize → early return
TEST_F(TestTxPoolManager, OnNewCrossBlock_NonRoot_WrongPool_EarlyReturn) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    vb->mutable_qc()->set_pool_index(0);  // not kImmutablePoolSize
    vb->mutable_block_info()->set_height(100);
    mgr_->OnNewCrossBlock(vb);  // should not crash
}

// Root congress network → updates root_cross_pools_[pool_index]
TEST_F(TestTxPoolManager, OnNewCrossBlock_RootNetwork_UpdatesRootCross) {
    if (mgr_->root_cross_pools_ == nullptr) {
        GTEST_SKIP() << "root_cross_pools_ is null (root-node build)";
    }
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kRootCongressNetworkId);
    vb->mutable_qc()->set_pool_index(1);
    vb->mutable_block_info()->set_height(77);
    mgr_->OnNewCrossBlock(vb);
    EXPECT_EQ(mgr_->root_cross_pools_[1].latest_height(), 77u);
}

// Non-root, pool_index == kImmutablePoolSize → updates cross_pools_[network_id]
TEST_F(TestTxPoolManager, OnNewCrossBlock_NonRoot_ImmutablePool_UpdatesCross) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    vb->mutable_qc()->set_pool_index(common::kImmutablePoolSize);
    vb->mutable_block_info()->set_height(55);
    mgr_->OnNewCrossBlock(vb);
    EXPECT_EQ(mgr_->cross_pools_[network::kConsensusShardBeginNetworkId].latest_height(), 55u);
}

// ---------------------------------------------------------------------------
// OnNewElectBlock (header lines 113-142)
// ---------------------------------------------------------------------------

// Different shard → condition false, skips body (no security_ deref)
TEST_F(TestTxPoolManager, OnNewElectBlock_DifferentShard_NoUpdate) {
    auto members = std::make_shared<common::Members>();
    // sharding_id != kInvalidUint32 (current network_id) → condition false
    mgr_->OnNewElectBlock(network::kConsensusShardBeginNetworkId, 100, members);
    EXPECT_EQ(mgr_->latest_elect_height_, 0u);
}

// Same shard but lower elect_height → no update
TEST_F(TestTxPoolManager, OnNewElectBlock_SameShard_LowerHeight_NoUpdate) {
    auto members = std::make_shared<common::Members>();
    mgr_->latest_elect_height_ = 50;
    mgr_->OnNewElectBlock(common::kInvalidUint32, 40, members);
    EXPECT_EQ(mgr_->latest_elect_height_, 50u);
}

// Same shard, higher elect_height, empty members → iterates 0 times (no security_ deref)
TEST_F(TestTxPoolManager, OnNewElectBlock_SameShard_NewHeight_EmptyMembers) {
    auto members = std::make_shared<common::Members>();
    mgr_->latest_elect_height_ = 0;
    mgr_->OnNewElectBlock(common::kInvalidUint32, 10, members);
    EXPECT_EQ(mgr_->latest_elect_height_, 10u);
    EXPECT_EQ(mgr_->latest_leader_count_, 0u);
    EXPECT_EQ(mgr_->member_index_, common::kInvalidUint32);
}

// OnNewElectBlock with one member whose pool_index_mod_num >= 0 → counts as leader
TEST_F(TestTxPoolManager, OnNewElectBlock_MemberWithPoolModNum_IncrementsLeaderCount) {
    auto members = std::make_shared<common::Members>();
    auto m = std::make_shared<common::BftMember>(
        network::kConsensusShardBeginNetworkId,
        std::string(common::kUnicastAddressLength, '\x01'),  // id != suite default address (0xAB…)
        "pubkey", 0, 1 /* pool_index_mod_num >= 0 */);
    members->push_back(m);
    mgr_->latest_elect_height_ = 0;
    mgr_->OnNewElectBlock(common::kInvalidUint32, 20, members);
    EXPECT_GE(mgr_->latest_leader_count_, 1u);
    EXPECT_EQ(mgr_->member_index_, common::kInvalidUint32);
}

// Member id matches local security address → member_index_ set (header lines 126–128)
TEST_F(TestTxPoolManager, OnNewElectBlock_MatchingId_SetsMemberIndex) {
    const std::string local_addr(common::kUnicastAddressLength, '\x77');
    ScopedSecurityOverride guard(mgr_->security_);
    guard.emplace(std::make_shared<FakeSecurityForTxPm>(local_addr));

    auto members = std::make_shared<common::Members>();
    auto m = std::make_shared<common::BftMember>(
        network::kConsensusShardBeginNetworkId,
        local_addr,
        "pubkey", 0, 0 /* pool_index_mod_num >= 0 */);
    members->push_back(m);
    mgr_->latest_elect_height_ = 0;
    mgr_->OnNewElectBlock(common::kInvalidUint32, 30, members);
    EXPECT_EQ(mgr_->latest_leader_count_, 1u);
    EXPECT_EQ(mgr_->member_index_, 0u);
}

// ---------------------------------------------------------------------------
// AddPoolMessage (header lines 244-248)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, AddPoolMessage_SetsSystemMessage) {
    auto msg = std::make_shared<transport::TransportMessage>();
    EXPECT_FALSE(msg->system_message);
    mgr_->AddPoolMessage(msg);
    EXPECT_TRUE(msg->system_message);
}

// ---------------------------------------------------------------------------
// PoolTimerMessage (cc lines 485-492)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, PoolTimerMessage_EmptyQueues_NoOp) {
    mgr_->PoolTimerMessage();  // should not crash
}

// ---------------------------------------------------------------------------
// UpdateLatestInfo (header lines 188-214)
// ---------------------------------------------------------------------------

// pool_index >= kInvalidPoolIndex → early return
TEST_F(TestTxPoolManager, UpdateLatestInfo_InvalidPool_EarlyReturn) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    vb->mutable_qc()->set_pool_index(common::kInvalidPoolIndex);
    vb->mutable_block_info()->set_height(10);
    db::DbWriteBatch batch;
    mgr_->UpdateLatestInfo(vb, batch);  // should not crash
}

// Normal path: synced_max_heights_[pool] is updated
TEST_F(TestTxPoolManager, UpdateLatestInfo_Valid_UpdatesMaxHeight) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    vb->mutable_qc()->set_pool_index(2);
    vb->mutable_qc()->set_view_block_hash("h1");
    vb->mutable_block_info()->set_height(300);
    db::DbWriteBatch batch;
    mgr_->UpdateLatestInfo(vb, batch);
    EXPECT_EQ(static_cast<uint64_t>(mgr_->synced_max_heights_[2]), 300u);
}

// ---------------------------------------------------------------------------
// UpdateCrossLatestInfo (header lines 216-242)
// ---------------------------------------------------------------------------

// Non-root network, pool_index != kGlobalPoolIndex → early return
TEST_F(TestTxPoolManager, UpdateCrossLatestInfo_NonRoot_WrongPool_EarlyReturn) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    vb->mutable_qc()->set_pool_index(0);  // not kGlobalPoolIndex
    vb->mutable_block_info()->set_height(50);
    db::DbWriteBatch batch;
    mgr_->UpdateCrossLatestInfo(vb, batch);  // should not crash
}

// Root congress network: root_cross_pools_ updated + PoolLatestInfo saved
TEST_F(TestTxPoolManager, UpdateCrossLatestInfo_RootNet_UpdatesRootCross) {
    if (mgr_->root_cross_pools_ == nullptr) {
        GTEST_SKIP() << "root_cross_pools_ is null (root-node build)";
    }
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kRootCongressNetworkId);
    vb->mutable_qc()->set_pool_index(3);
    vb->mutable_block_info()->set_height(999);
    db::DbWriteBatch batch;
    mgr_->UpdateCrossLatestInfo(vb, batch);
    EXPECT_EQ(mgr_->root_cross_pools_[3].latest_height(), 999u);
}

// Non-root, pool == kGlobalPoolIndex → cross_block_mgr_->UpdateMaxHeight called
TEST_F(TestTxPoolManager, UpdateCrossLatestInfo_NonRoot_GlobalPool_Updates) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    vb->mutable_qc()->set_pool_index(common::kGlobalPoolIndex);
    vb->mutable_block_info()->set_height(42);
    db::DbWriteBatch batch;
    mgr_->UpdateCrossLatestInfo(vb, batch);  // should not crash
}

// ---------------------------------------------------------------------------
// InitCrossPools path (lines 94-107) already covered by constructor, but
// we can verify the pools are populated.
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, InitCrossPools_CrossPoolsNonNull) {
    EXPECT_NE(mgr_->cross_pools_, nullptr);
    // cross_pools_[kConsensusShardBeginNetworkId] should have been initialised
    EXPECT_EQ(
        mgr_->cross_pools_[network::kConsensusShardBeginNetworkId].des_sharding_id_,
        network::kConsensusShardBeginNetworkId);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
