#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "common/global_info.h"
#include "pools/tx_utils.h"
#include "pools/unique_hash_lru_set.h"
#include "pools/account_qps_lru_map.h"

namespace shardora {

namespace {

pools::protobuf::TxMessage MakeTxMessage(const std::string& seed) {
    pools::protobuf::TxMessage tx;
    tx.set_nonce(seed.size());
    tx.set_pubkey("pubkey_" + seed);
    tx.set_to("to_" + seed);
    tx.set_amount(seed.size() + 1);
    tx.set_gas_limit(21000);
    tx.set_gas_price(1);
    tx.set_step(pools::protobuf::kNormalFrom);
    return tx;
}

}  // namespace

TEST(TestPoolsSmoke, BuildOnly) {
    SUCCEED();
}

// Test basic tx_utils functionality
TEST(TestPoolsSmoke, TxUtilsBasicFunctions) {
    // Test GetTxMessageHash function
    auto test_data = MakeTxMessage("test_transaction_data");
    std::string hash1 = pools::GetTxMessageHash(test_data);
    std::string hash2 = pools::GetTxMessageHash(test_data);

    // Same input should produce same hash
    EXPECT_EQ(hash1, hash2);
    EXPECT_FALSE(hash1.empty());

    // Different input should produce different hash
    auto different_data = MakeTxMessage("different_transaction_data");
    std::string hash3 = pools::GetTxMessageHash(different_data);
    EXPECT_NE(hash1, hash3);
}

// Test UniqueHashLruSet basic functionality
TEST(TestPoolsSmoke, UniqueHashLruSetBasicOperations) {
    pools::UniqueHashLruSet<10> lru_set;

    // Test empty set
    EXPECT_FALSE(lru_set.exists("hash1"));

    // Test adding elements
    lru_set.insert("hash1");
    EXPECT_TRUE(lru_set.exists("hash1"));

    lru_set.insert("hash2");
    EXPECT_TRUE(lru_set.exists("hash1"));
    EXPECT_TRUE(lru_set.exists("hash2"));

    // Test duplicate insertion
    lru_set.insert("hash1");
    EXPECT_TRUE(lru_set.exists("hash1"));
}

// Test UniqueHashLruSet capacity limits
TEST(TestPoolsSmoke, UniqueHashLruSetCapacityLimit) {
    pools::UniqueHashLruSet<3> small_lru_set;

    // Fill beyond capacity
    small_lru_set.insert("hash1");
    small_lru_set.insert("hash2");
    small_lru_set.insert("hash3");
    small_lru_set.insert("hash4"); // Should evict oldest

    EXPECT_FALSE(small_lru_set.exists("hash1")); // Should be evicted
    EXPECT_TRUE(small_lru_set.exists("hash2"));
    EXPECT_TRUE(small_lru_set.exists("hash3"));
    EXPECT_TRUE(small_lru_set.exists("hash4"));
}

// Test AccountQpsLruMap basic functionality
TEST(TestPoolsSmoke, AccountQpsLruMapBasicOperations) {
    pools::AccountQpsLruMap<100> qps_map;

    std::string account1 = "account_address_1";
    std::string account2 = "account_address_2";

    EXPECT_TRUE(qps_map.check(account1));
    EXPECT_TRUE(qps_map.check(account1));
    EXPECT_TRUE(qps_map.check(account2));
}

// Test AccountQpsLruMap with many accounts
TEST(TestPoolsSmoke, AccountQpsLruMapManyAccounts) {
    pools::AccountQpsLruMap<50> qps_map;

    // Add many accounts
    for (int i = 0; i < 100; ++i) {
        std::string account = "account_" + std::to_string(i);
        EXPECT_TRUE(qps_map.check(account));
    }

    // Some early accounts might be evicted due to capacity limit
    // But recent ones should still exist
    for (int i = 90; i < 100; ++i) {
        std::string account = "account_" + std::to_string(i);
        EXPECT_TRUE(qps_map.check(account));
    }
}

// Test edge cases with empty strings
TEST(TestPoolsSmoke, EdgeCasesWithEmptyStrings) {
    // Test hash function with empty string
    std::string empty_hash = pools::GetTxMessageHash(MakeTxMessage(""));
    EXPECT_FALSE(empty_hash.empty());

    // Test LRU set with empty string
    pools::UniqueHashLruSet<10> lru_set;
    lru_set.insert("");
    EXPECT_TRUE(lru_set.exists(""));

    // Test QPS map with empty account
    pools::AccountQpsLruMap<10> qps_map;
    EXPECT_TRUE(qps_map.check(""));
}

// Test with very long strings
TEST(TestPoolsSmoke, LongStringHandling) {
    std::string long_string(10000, 'a');

    // Test hash function with long string
    std::string hash = pools::GetTxMessageHash(MakeTxMessage(long_string));
    EXPECT_FALSE(hash.empty());

    // Test LRU set with long string
    pools::UniqueHashLruSet<5> lru_set;
    lru_set.insert(long_string);
    EXPECT_TRUE(lru_set.exists(long_string));

    // Test QPS map with long account name
    pools::AccountQpsLruMap<5> qps_map;
    EXPECT_TRUE(qps_map.check(long_string));
}

// Test concurrent-like operations (single-threaded simulation)
TEST(TestPoolsSmoke, ConcurrentLikeOperations) {
    pools::UniqueHashLruSet<100> lru_set;
    pools::AccountQpsLruMap<100> qps_map;

    // Simulate multiple operations
    for (int i = 0; i < 1000; ++i) {
        std::string hash = "hash_" + std::to_string(i % 50);
        std::string account = "account_" + std::to_string(i % 20);

        lru_set.insert(hash);

        EXPECT_TRUE(lru_set.exists(hash));
        EXPECT_TRUE(qps_map.check(account));
    }
}

}  // namespace shardora
