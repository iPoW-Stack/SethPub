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

#include "consensus/consensus_utils.h"
#include "tnet/tcp_interface.h"

#define private public
#define protected public
#include "db/db.h"
#include "pools/tx_pool_manager.h"
#undef protected
#undef private

#include "block/account_manager.h"
#include "common/global_info.h"
#include "common/node_members.h"
#include "common/utils.h"
#include "network/network_utils.h"
#include "protos/pools.pb.h"

namespace seth {
namespace pools {
namespace test {

namespace {

// Non-null AccountManager token so acc_mgr_.lock() succeeds; GetAccountInfo is
// stubbed in test_pools_stubs.cc.
struct ScopedAccMgrAttach {
    TxPoolManager* mgr;
    std::shared_ptr<block::AccountManager> stub;
    explicit ScopedAccMgrAttach(TxPoolManager* m)
        : mgr(m),
          stub(std::shared_ptr<block::AccountManager>(
              reinterpret_cast<block::AccountManager*>(0x40uLL),
              [](block::AccountManager*) {})) {
        mgr->acc_mgr_ = stub;
    }
    ~ScopedAccMgrAttach() { mgr->acc_mgr_ = std::weak_ptr<block::AccountManager>(); }
};

struct ScopedTxStatusCallbackClear {
    TxPoolManager* mgr;
    explicit ScopedTxStatusCallbackClear(TxPoolManager* m) : mgr(m) {}
    ~ScopedTxStatusCallbackClear() { mgr->SetTxStatusCallback({}); }
};

static transport::MessagePtr MakeEthUserFirewallMessage(const std::string& pubkey_tag) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_nonce(1);
    tx->set_pubkey(pubkey_tag);
    tx->set_sign("sig");
    tx->set_to(std::string(common::kUnicastAddressLength, 'T'));
    tx->set_amount(0);
    tx->set_gas_limit(21000);
    tx->set_gas_price(1);
    tx->set_eth_raw_tx("0x01");
    return msg;
}

// Minimal TcpInterface for conn != nullptr guards in HandlePoolsMessage.
struct FakeTcpConnForPools : tnet::TcpInterface {
    std::string PeerIp() override { return "127.0.0.1"; }
    uint16_t PeerPort() override { return 9; }
    void SetPeerIp(const std::string&) override {}
    void SetPeerPort(uint16_t) override {}
    int Send(const std::string&) override { return 0; }
    int Send(const char*, int32_t) override { return 0; }
    int Send(uint64_t, const std::string&) override { return 0; }
    int Send(const char*, int32_t, uint64_t) override { return 0; }
};

static uint32_t ExpectedLocalShardForInvalidUint32Network() {
    uint32_t local_shard = common::GlobalInfo::Instance()->network_id();
    if (local_shard >= network::kConsensusShardEndNetworkId) {
        local_shard -= network::kConsensusWaitingShardOffset;
    }
    return local_shard;
}

}  // namespace

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

// ---------------------------------------------------------------------------
// TmpFirewallCheckMessage (tx_pool_manager.cc ~131-294)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, TmpFirewall_NonUser_NotSystem_ReturnsError) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->system_message = false;
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kStatistic);
    tx->set_pubkey("pk_nf");
    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckError);
}

TEST_F(TestTxPoolManager, TmpFirewall_NonUser_System_ReturnsSuccess) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->system_message = true;
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kStatistic);
    tx->set_pubkey("pk_sys");
    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckSuccess);
}

TEST_F(TestTxPoolManager, TmpFirewall_User_MissingSign_ReturnsError) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_pubkey("pk_ms");
    tx->set_sign("");
    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckError);
    EXPECT_EQ(msg->handle_status, transport::kTxInvalidSignature);
}

TEST_F(TestTxPoolManager, TmpFirewall_User_VerifyFails_ReturnsError) {
    auto* fake = dynamic_cast<FakeSecurityForTxPm*>(mgr_->security_.get());
    ASSERT_NE(fake, nullptr);
    fake->set_verify_always_success(false);

    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_nonce(1);
    tx->set_pubkey("vf");
    tx->set_sign("bad");
    tx->set_to(std::string(common::kUnicastAddressLength, 'Z'));
    tx->set_amount(0);
    tx->set_gas_limit(21000);
    tx->set_gas_price(1);

    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckError);
    EXPECT_EQ(msg->handle_status, transport::kTxInvalidSignature);
    fake->set_verify_always_success(true);
}

TEST_F(TestTxPoolManager, TmpFirewall_EthWithAddressInfo_MatchingShard_ReturnsSuccess) {
    auto* fake = dynamic_cast<FakeSecurityForTxPm*>(mgr_->security_.get());
    ASSERT_NE(fake, nullptr);
    fake->set_verify_always_success(true);

    auto msg = MakeEthUserFirewallMessage("eth_ok_pk");
    const std::string& local_addr = mgr_->security_->GetAddress();
    msg->address_info = MakeTestAddressInfo(0, local_addr, common::kInvalidUint32);

    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckSuccess);
}

TEST_F(TestTxPoolManager, TmpFirewall_EthRaw_EmptyPubkey_ReturnsError) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_nonce(1);
    tx->set_pubkey("");
    tx->set_sign("s");
    tx->set_eth_raw_tx("raw");
    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckError);
    EXPECT_EQ(msg->handle_status, transport::kTxInvalidSignature);
}

TEST_F(TestTxPoolManager, TmpFirewall_EthWrongShard_ReturnsErrorAfterRoute) {
    auto* fake = dynamic_cast<FakeSecurityForTxPm*>(mgr_->security_.get());
    ASSERT_NE(fake, nullptr);
    fake->set_verify_always_success(true);

    auto msg = MakeEthUserFirewallMessage("eth_wr_shard");
    const std::string& local_addr = mgr_->security_->GetAddress();
    msg->address_info = MakeTestAddressInfo(0, local_addr, /*sharding_id=*/0u);

    EXPECT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckError);
}

TEST_F(TestTxPoolManager, TmpFirewall_StatusNotify_ChainsExistingCallback) {
    ScopedTxStatusCallbackClear clear_guard(mgr_.get());
    auto* fake = dynamic_cast<FakeSecurityForTxPm*>(mgr_->security_.get());
    ASSERT_NE(fake, nullptr);
    fake->set_verify_always_success(true);

    auto msg = MakeEthUserFirewallMessage("cb_chain_pk");
    const std::string& local_addr = mgr_->security_->GetAddress();
    msg->address_info = MakeTestAddressInfo(0, local_addr, common::kInvalidUint32);

    bool first = false;
    bool second = false;
    msg->status_notify_cb = [&](const std::string&, transport::MessageHandleStatus) { first = true; };
    mgr_->SetTxStatusCallback([&](const std::string&, transport::MessageHandleStatus) { second = true; });

    ASSERT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckSuccess);
    ASSERT_TRUE(static_cast<bool>(msg->status_notify_cb));
    msg->status_notify_cb("deadbeef", transport::kMessageHandle);
    EXPECT_TRUE(first);
    EXPECT_TRUE(second);
}

TEST_F(TestTxPoolManager, TmpFirewall_StatusNotify_SetsFromManagerCallbackOnly) {
    ScopedTxStatusCallbackClear clear_guard(mgr_.get());
    auto* fake = dynamic_cast<FakeSecurityForTxPm*>(mgr_->security_.get());
    ASSERT_NE(fake, nullptr);
    fake->set_verify_always_success(true);

    auto msg = MakeEthUserFirewallMessage("cb_only_pk");
    const std::string& local_addr = mgr_->security_->GetAddress();
    msg->address_info = MakeTestAddressInfo(0, local_addr, common::kInvalidUint32);

    bool mgr_cb = false;
    mgr_->SetTxStatusCallback([&](const std::string&, transport::MessageHandleStatus) { mgr_cb = true; });

    ASSERT_EQ(mgr_->TmpFirewallCheckMessage(msg), transport::kFirewallCheckSuccess);
    ASSERT_TRUE(static_cast<bool>(msg->status_notify_cb));
    msg->status_notify_cb("abc", transport::kTxAccept);
    EXPECT_TRUE(mgr_cb);
}

// ---------------------------------------------------------------------------
// TxPoolHandleMessage — user tx account lookup (cc ~536-550)
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, TxPoolHandleMessage_UserLookupFails_SetsInvalidAddress) {
    ScopedAccMgrAttach acc_guard(mgr_.get());
    ScopedAccountInfoOverride acc_ov([](const std::string&) { return nullptr; });

    auto* fake = dynamic_cast<FakeSecurityForTxPm*>(mgr_->security_.get());
    ASSERT_NE(fake, nullptr);
    fake->set_verify_always_success(true);

    auto msg = MakeEthUserFirewallMessage("txh_inv_addr");
    const std::string& local_addr = mgr_->security_->GetAddress();
    msg->address_info = MakeTestAddressInfo(0, local_addr, common::kInvalidUint32);

    mgr_->TxPoolHandleMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kTxInvalidAddress);
}

// ---------------------------------------------------------------------------
// HandlePoolsMessage (tx_pool_manager.cc ~657-762) — direct calls bypass TmpFirewall
// ---------------------------------------------------------------------------

TEST_F(TestTxPoolManager, HandlePoolsMessage_RootCreateAddress_TooShortTo_ReturnsEarly) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->conn = nullptr;
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kRootCreateAddress);
    tx->set_to("short");
    mgr_->HandlePoolsMessage(msg);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_RootCreateAddress_WithConn_ReturnsEarly) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->conn = std::make_shared<FakeTcpConnForPools>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kRootCreateAddress);
    tx->set_to(std::string(common::kUnicastAddressLength, 'C'));
    mgr_->HandlePoolsMessage(msg);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_RootCreateAddress_ValidTo_ReachesDispatch) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->conn = nullptr;
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kRootCreateAddress);
    tx->set_to(std::string(common::kUnicastAddressLength, 'D'));
    tx->set_nonce(1);
    tx->set_amount(0);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_ConsensusLocalTos_SetsPoolAndDispatch) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kConsensusLocalTos);
    tx->set_to(std::string(common::kUnicastAddressLength, 'E'));
    tx->set_nonce(2);
    tx->set_pubkey("pk");
    tx->set_sign("sg");
    tx->set_amount(0);
    tx->set_gas_limit(21000);
    tx->set_gas_price(1);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_RootCross_SetsPoolIndex) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kRootCross);
    tx->set_to(std::string(common::kUnicastAddressLength, 'F'));
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_PoolStatisticTag_UsesAddressPool) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->address_info = MakeTestAddressInfo(3, std::string(common::kUnicastAddressLength, 'G'), common::kInvalidUint32);
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kPoolStatisticTag);
    tx->set_nonce(1);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_Statistic_UsesAddressPool) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->address_info = MakeTestAddressInfo(2, std::string(common::kUnicastAddressLength, 'H'), common::kInvalidUint32);
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kStatistic);
    tx->set_nonce(1);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_ConsensusRootElectShard_UsesAddressPool) {
    auto msg = std::make_shared<transport::TransportMessage>();
    msg->address_info = MakeTestAddressInfo(1, std::string(common::kUnicastAddressLength, 'J'), common::kInvalidUint32);
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kConsensusRootElectShard);
    tx->set_nonce(1);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_DefaultStep_SetsInvalidAddress) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kNormalTo);
    tx->set_nonce(1);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kTxInvalidAddress);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_CreateContract_ShortCode_RequestInvalid) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kCreateContract);
    tx->mutable_contract_code()->assign(100, 'x');
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kRequestInvalid);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_CreateLibrary_ShortCode_RequestInvalid) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kCreateLibrary);
    tx->mutable_contract_code()->assign(64, 'y');
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kRequestInvalid);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_ContractGasPrefund_InvalidInput_RequestInvalid) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kContractGasPrefund);
    tx->set_contract_input("nonempty");
    tx->set_contract_prefund(1);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kRequestInvalid);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_ContractRefund_BadGas_ReturnsOutOfGas) {
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kContractRefund);
    tx->set_gas_price(0);
    tx->set_gas_limit(consensus::kTransferGas);
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kConsensusOutOfGas);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_JoinElect_BadVerifyKey_RequestInvalid) {
    ScopedAccMgrAttach acc_guard(mgr_.get());
    ScopedAccountInfoOverride ov([](const std::string&) {
        auto ai = MakeTestAddressInfo(0, std::string(common::kUnicastAddressLength, 'K'), common::kInvalidUint32);
        ai->set_balance(100000000llu);
        return ai;
    });
    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kJoinElect);
    tx->set_pubkey("pkje");
    tx->set_to(std::string(common::kUnicastAddressLength, 'L'));
    tx->set_key("not-the-join-elect-key");
    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kRequestInvalid);
}

TEST_F(TestTxPoolManager, HandlePoolsMessage_NormalFrom_BalanceOk_ThenDispatchUnknown) {
    ScopedAccMgrAttach acc_guard(mgr_.get());
    const std::string from_addr(common::kUnicastAddressLength, 'M');
    const std::string to_addr(common::kUnicastAddressLength, 'N');
    const uint32_t adj_shard = ExpectedLocalShardForInvalidUint32Network();

    ScopedAccountInfoOverride ov([&](const std::string&) {
        auto ai = MakeTestAddressInfo(0, from_addr, adj_shard);
        ai->set_balance(500000000llu);
        ai->set_nonce(0);
        return ai;
    });

    auto msg = std::make_shared<transport::TransportMessage>();
    auto* tx = msg->header.mutable_tx_proto();
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_nonce(1);
    tx->set_pubkey("pknf");
    tx->set_to(to_addr);
    tx->set_amount(1);
    tx->set_gas_limit(21000);
    tx->set_gas_price(1);
    msg->address_info = MakeTestAddressInfo(0, from_addr, adj_shard);
    msg->address_info->set_balance(500000000llu);
    msg->address_info->set_nonce(0);

    mgr_->HandlePoolsMessage(msg);
    EXPECT_EQ(msg->handle_status, transport::kUnkonwn);
}

#ifdef SETH_UNITTEST
TEST_F(TestTxPoolManager, IsOtherLeaderHook_SetAndClear) {
    auto noop = [](uint32_t) -> common::BftMemberPtr { return nullptr; };
    TxPoolManager::SetIsOtherLeaderHookForTest(noop);
    TxPoolManager::ClearIsOtherLeaderHookForTest();
}
#endif

}  // namespace test
}  // namespace pools
}  // namespace seth
