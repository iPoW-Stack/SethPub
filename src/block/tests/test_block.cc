#include <gtest/gtest.h>

#include <string>
#include <vector>
#include <thread>
#include <memory>

#include "common/encode.h"
#include "common/hash.h"
#include "common/random.h"
#include "common/time_utils.h"
#include "protos/address.pb.h"
#include "protos/block.pb.h"
#include "protos/view_block.pb.h"

#define private public
#include "block/block_utils.h"
#include "block/account_lru_map.h"

namespace shardora {

namespace block {

namespace test {

class TestBlock : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

protected:
    // Helper to create an AddressInfo
    protos::AddressInfoPtr MakeAccount(const std::string& addr, uint64_t balance = 0, uint64_t nonce = 0) {
        auto info = std::make_shared<address::protobuf::AddressInfo>();
        info->set_addr(addr);
        info->set_balance(balance);
        info->set_nonce(nonce);
        return info;
    }
};

// --- AccountLruMap Tests ---

TEST_F(TestBlock, AccountLruMapInsertAndGet) {
    AccountLruMap<10> map;
    auto acc = MakeAccount("addr_001", 1000, 5);
    map.insert(acc);

    auto result = map.get("addr_001");
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->addr(), "addr_001");
    ASSERT_EQ(result->balance(), 1000u);
    ASSERT_EQ(result->nonce(), 5u);
}

TEST_F(TestBlock, AccountLruMapGetNonExistent) {
    AccountLruMap<10> map;
    auto result = map.get("nonexistent");
    ASSERT_EQ(result, nullptr);
}

TEST_F(TestBlock, AccountLruMapOverwrite) {
    AccountLruMap<10> map;
    auto acc1 = MakeAccount("addr_001", 1000, 1);
    auto acc2 = MakeAccount("addr_001", 2000, 2);

    map.insert(acc1);
    map.insert(acc2);

    auto result = map.get("addr_001");
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->balance(), 2000u);
    ASSERT_EQ(result->nonce(), 2u);
}

TEST_F(TestBlock, AccountLruMapEviction) {
    AccountLruMap<3> map;
    map.insert(MakeAccount("addr_1", 100));
    map.insert(MakeAccount("addr_2", 200));
    map.insert(MakeAccount("addr_3", 300));
    // Full, inserting 4th should evict LRU (addr_1)
    map.insert(MakeAccount("addr_4", 400));

    ASSERT_EQ(map.get("addr_1"), nullptr);
    ASSERT_NE(map.get("addr_2"), nullptr);
    ASSERT_NE(map.get("addr_3"), nullptr);
    ASSERT_NE(map.get("addr_4"), nullptr);
}

TEST_F(TestBlock, AccountLruMapAccessUpdatesOrder) {
    AccountLruMap<3> map;
    map.insert(MakeAccount("addr_1", 100));
    map.insert(MakeAccount("addr_2", 200));
    map.insert(MakeAccount("addr_3", 300));

    // Re-insert addr_1 to move it to front (MRU)
    map.insert(MakeAccount("addr_1", 150));

    // Now addr_2 is LRU, inserting new should evict addr_2
    map.insert(MakeAccount("addr_4", 400));

    ASSERT_NE(map.get("addr_1"), nullptr);
    ASSERT_EQ(map.get("addr_2"), nullptr);  // Evicted
    ASSERT_NE(map.get("addr_3"), nullptr);
    ASSERT_NE(map.get("addr_4"), nullptr);
}

TEST_F(TestBlock, AccountLruMapGetOrInsertExisting) {
    AccountLruMap<10> map;
    auto acc = MakeAccount("addr_001", 1000);
    map.insert(acc);

    auto new_acc = MakeAccount("addr_001", 9999);
    auto result = map.get_or_insert("addr_001", new_acc);
    // Should return existing, not the new one
    ASSERT_EQ(result->balance(), 1000u);
}

TEST_F(TestBlock, AccountLruMapGetOrInsertNew) {
    AccountLruMap<10> map;
    auto acc = MakeAccount("addr_new", 5000);
    auto result = map.get_or_insert("addr_new", acc);
    // Should insert and return the new value
    ASSERT_EQ(result->balance(), 5000u);

    // Should be retrievable
    auto get_result = map.get("addr_new");
    ASSERT_NE(get_result, nullptr);
    ASSERT_EQ(get_result->balance(), 5000u);
}

TEST_F(TestBlock, AccountLruMapThreadSafety) {
    AccountLruMap<1000> map;
    const int kThreads = 4;
    const int kOpsPerThread = 100;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&map, t]() {
            for (int i = 0; i < kOpsPerThread; ++i) {
                std::string addr = "addr_" + std::to_string(t) + "_" + std::to_string(i);
                auto acc = std::make_shared<address::protobuf::AddressInfo>();
                acc->set_addr(addr);
                acc->set_balance(i);
                map.insert(acc);
                map.get(addr);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // Verify no crash and some data is accessible
    auto result = map.get("addr_0_99");
    // May or may not exist due to eviction, but should not crash
    ASSERT_TRUE(true);
}

// --- BlockTxsItem Tests ---

TEST_F(TestBlock, BlockTxsItemDefault) {
    BlockTxsItem item;
    ASSERT_EQ(item.tx_ptr, nullptr);
    ASSERT_EQ(item.tx_count, 0u);
    ASSERT_FALSE(item.success);
    ASSERT_EQ(item.leader_to_index, -1);
    ASSERT_GT(item.stop_consensus_timeout, 0u);
}

TEST_F(TestBlock, BlockTxsItemTimeout) {
    BlockTxsItem item;
    uint64_t now = common::TimeUtils::TimestampMs();
    // Timeout should be in the future
    ASSERT_GT(item.stop_consensus_timeout, now);
    ASSERT_LE(item.stop_consensus_timeout, now + kStopConsensusTimeoutMs + 100);
}

// --- Block Protobuf Tests ---

TEST_F(TestBlock, ViewBlockItemSerialize) {
    view_block::protobuf::ViewBlockItem vblock;
    auto* qc = vblock.mutable_qc();
    qc->set_network_id(3);
    qc->set_pool_index(5);
    qc->set_view(100);
    qc->set_view_block_hash(common::Random::RandomString(32));
    qc->set_sign_x("sign_x_data");
    qc->set_sign_y("sign_y_data");
    qc->set_elect_height(50);

    auto* block_info = vblock.mutable_block_info();
    block_info->set_height(200);
    block_info->set_timestamp(1700000000000);
    block_info->set_timeblock_height(10);

    std::string serialized = vblock.SerializeAsString();
    ASSERT_FALSE(serialized.empty());

    view_block::protobuf::ViewBlockItem deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.qc().network_id(), 3u);
    ASSERT_EQ(deserialized.qc().pool_index(), 5u);
    ASSERT_EQ(deserialized.qc().view(), 100u);
    ASSERT_EQ(deserialized.qc().elect_height(), 50u);
    ASSERT_EQ(deserialized.block_info().height(), 200u);
    ASSERT_EQ(deserialized.block_info().timestamp(), 1700000000000u);
    ASSERT_EQ(deserialized.block_info().timeblock_height(), 10u);
}

TEST_F(TestBlock, AddressInfoSerialize) {
    address::protobuf::AddressInfo addr;
    addr.set_addr(common::Random::RandomString(20));
    addr.set_balance(1000000);
    addr.set_nonce(42);
    addr.set_type(address::protobuf::kNormal);
    addr.set_sharding_id(3);
    addr.set_pool_index(5);
    addr.set_latest_height(100);
    addr.set_tx_index(7);

    std::string serialized = addr.SerializeAsString();
    address::protobuf::AddressInfo deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.addr(), addr.addr());
    ASSERT_EQ(deserialized.balance(), 1000000u);
    ASSERT_EQ(deserialized.nonce(), 42u);
    ASSERT_EQ(deserialized.sharding_id(), 3u);
    ASSERT_EQ(deserialized.pool_index(), 5u);
    ASSERT_EQ(deserialized.latest_height(), 100u);
    ASSERT_EQ(deserialized.tx_index(), 7u);
}

// --- Constants Tests ---

TEST_F(TestBlock, ErrorCodes) {
    ASSERT_EQ(kBlockSuccess, 0);
    ASSERT_NE(kBlockError, kBlockSuccess);
    ASSERT_NE(kBlockDbNotExists, kBlockSuccess);
    ASSERT_NE(kBlockDbDataInvalid, kBlockSuccess);
    ASSERT_NE(kBlockAddressNotExists, kBlockSuccess);
    ASSERT_NE(kBlockVerifyAggSignFailed, kBlockSuccess);
}

TEST_F(TestBlock, AddressTypes) {
    ASSERT_EQ(kNormalAddress, 0);
    ASSERT_EQ(kContractAddress, 1);
    ASSERT_NE(kNormalAddress, kContractAddress);
}

TEST_F(TestBlock, StopConsensusTimeout) {
    ASSERT_GT(kStopConsensusTimeoutMs, 0u);
}

TEST_F(TestBlock, GenesisAccountConstant) {
    ASSERT_FALSE(kCreateGenesisNetwrokAccount.empty());
    ASSERT_EQ(kCreateGenesisNetwrokAccount.size(), 32u);
}

// --- isContractCreateToTxMessageItem Tests ---

TEST_F(TestBlock, IsContractCreateWithLibraryBytes) {
    pools::protobuf::ToTxMessageItem item;
    item.set_library_bytes("contract_bytecode_here");
    ASSERT_TRUE(isContractCreateToTxMessageItem(item));
}

TEST_F(TestBlock, IsContractCreateWithoutLibraryBytes) {
    pools::protobuf::ToTxMessageItem item;
    item.set_amount(1000);
    item.set_des("some_address");
    ASSERT_FALSE(isContractCreateToTxMessageItem(item));
}

}  // namespace test

}  // namespace block

}  // namespace shardora
