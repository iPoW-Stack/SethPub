// Function-coverage tests for hotstuff::CheckTransactionValid (utils.cc).

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

#include "block/account_manager.h"
#include "block/block_manager.h"
#include "common/global_info.h"
#include "consensus/hotstuff/utils.h"
#include "consensus/hotstuff/view_block_chain.h"
#include "db/db.h"
#include "pools/tx_pool_manager.h"
#include "protos/prefix_db.h"
#include "security/ecdsa/ecdsa.h"
#include "sync/key_value_sync.h"

namespace shardora {
namespace consensus {
namespace test {

namespace {

constexpr const char* kDbPath = "./consensus_check_tx_db";

static std::shared_ptr<sync::KeyValueSync> MakeKvStub() {
    auto* raw = reinterpret_cast<sync::KeyValueSync*>(1uLL);
    return std::shared_ptr<sync::KeyValueSync>(raw, [](sync::KeyValueSync*) {});
}

class CheckTransactionValidFixture : public ::testing::Test {
protected:
    void SetUp() override {
        (void)std::system("rm -rf ./consensus_check_tx_db");
        prev_net_ = common::GlobalInfo::Instance()->network_id();
        common::GlobalInfo::Instance()->set_network_id(common::kInvalidUint32);

        db_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_->Init(kDbPath));
        prefix_db_ = std::make_shared<protos::PrefixDb>(db_);
        security_ = std::make_shared<security::Ecdsa>();
        std::shared_ptr<block::AccountManager> null_acc;
        std::shared_ptr<consensus::HotstuffManager> null_hotstuff;
        pools_mgr_ = std::make_shared<pools::TxPoolManager>(
            security_, db_, MakeKvStub(), null_acc, null_hotstuff);
        account_mgr_ = std::make_shared<block::AccountManager>();
        ASSERT_EQ(account_mgr_->Init(db_, pools_mgr_), 0);
        block_mgr_ = std::make_shared<block::BlockManager>();
        chain_ = std::make_shared<hotstuff::ViewBlockChain>();
        chain_->Init(
            hotstuff::kLocalChain,
            0,
            db_,
            block_mgr_,
            account_mgr_,
            nullptr,
            nullptr,
            pools_mgr_,
            nullptr);
    }

    void TearDown() override {
        chain_.reset();
        block_mgr_.reset();
        account_mgr_.reset();
        pools_mgr_.reset();
        security_.reset();
        prefix_db_.reset();
        db_.reset();
        common::GlobalInfo::Instance()->set_network_id(prev_net_);
        (void)std::system("rm -rf ./consensus_check_tx_db");
    }

    void PutAccount(const std::string& addr, uint64_t nonce, bool destructed = false) {
        address::protobuf::AddressInfo info;
        info.set_addr(addr);
        info.set_nonce(nonce);
        info.set_destructed(destructed);
        db::DbWriteBatch batch;
        prefix_db_->AddAddressInfo(addr, info, batch);
        ASSERT_TRUE(db_->Put(batch).ok());
    }

    int CheckTx(
            uint32_t step,
            const std::string& from_addr,
            const std::string& to_addr = "",
            uint64_t nonce = 1,
            const std::string& key = "k") {
        address::protobuf::AddressInfo addr_info;
        addr_info.set_addr(from_addr);
        addr_info.set_pool_index(0);
        pools::protobuf::TxMessage tx;
        tx.set_step(step);
        tx.set_from(from_addr);
        tx.set_to(to_addr.empty() ? from_addr : to_addr);
        tx.set_nonce(nonce);
        tx.set_key(key);
        uint64_t now_nonce = 0;
        return hotstuff::CheckTransactionValid(
            "",
            chain_,
            pools_mgr_,
            addr_info,
            tx,
            &now_nonce);
    }

    std::shared_ptr<db::Db> db_;
    std::shared_ptr<protos::PrefixDb> prefix_db_;
    std::shared_ptr<security::Security> security_;
    std::shared_ptr<pools::TxPoolManager> pools_mgr_;
    std::shared_ptr<block::AccountManager> account_mgr_;
    std::shared_ptr<block::BlockManager> block_mgr_;
    std::shared_ptr<hotstuff::ViewBlockChain> chain_;
    uint32_t prev_net_{common::kInvalidUint32};
};

}  // namespace

TEST_F(CheckTransactionValidFixture, UserTxMissingAccountReturnsNegativeOne) {
    const std::string addr = std::string(20, '\x01');
    EXPECT_EQ(CheckTx(pools::protobuf::kNormalFrom, addr), -1);
}

TEST_F(CheckTransactionValidFixture, UserTxValidNonceReturnsZero) {
    const std::string addr = std::string(20, '\x02');
    PutAccount(addr, 0);
    EXPECT_EQ(CheckTx(pools::protobuf::kNormalFrom, addr, addr, 1), 0);
}

TEST_F(CheckTransactionValidFixture, ContractExecuteMissingContractReturnsThree) {
    const std::string from = std::string(20, '\x03');
    const std::string to = std::string(20, '\x04');
    PutAccount(from, 0);
    EXPECT_EQ(
        CheckTx(pools::protobuf::kContractExcute, from, to, 1),
        3);
}

TEST_F(CheckTransactionValidFixture, ContractExecuteDestructedContractReturnsThree) {
    const std::string from = std::string(20, '\x05');
    const std::string to = std::string(20, '\x06');
    PutAccount(from, 0);
    PutAccount(to, 0, true);
    EXPECT_EQ(
        CheckTx(pools::protobuf::kContractExcute, from, to, 1),
        3);
}

TEST_F(CheckTransactionValidFixture, PoolStatisticTagNonceFailurePropagates) {
    const std::string addr = std::string(20, '\x07');
    EXPECT_EQ(
        CheckTx(pools::protobuf::kPoolStatisticTag, addr, addr, 1),
        -1);
}

TEST_F(CheckTransactionValidFixture, PoolStatisticTagMissingTxKeyReturnsNegativeOne) {
    const std::string addr = std::string(20, '\x08');
    PutAccount(addr, 0);
    EXPECT_EQ(
        CheckTx(pools::protobuf::kPoolStatisticTag, addr, addr, 1, "missing_key"),
        -1);
}

TEST_F(CheckTransactionValidFixture, NonUserTxWithoutStorageReturnsZero) {
    const std::string addr = std::string(20, '\x09');
    EXPECT_EQ(CheckTx(pools::protobuf::kNormalTo, addr), 0);
}

}  // namespace test
}  // namespace consensus
}  // namespace shardora
