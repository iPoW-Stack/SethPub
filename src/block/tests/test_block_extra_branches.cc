// Additional branch-coverage tests for block module.
// Covers AccountLruMap::get_or_insert eviction path,
// insert with existing key, isContractCreateToTxMessageItem,
// and struct default-value branches.

#include <gtest/gtest.h>
#include "block/account_lru_map.h"
#include "block/block_utils.h"
#include "protos/address.pb.h"
#include "protos/pools.pb.h"

namespace seth {
namespace block {
namespace test {

static AccountPtr MakeAddr(const std::string& id) {
    auto a = std::make_shared<address::protobuf::AddressInfo>();
    a->set_addr(id);
    a->set_balance(100);
    return a;
}

// ---- AccountLruMap::insert branches ----

TEST(AccountLruMapExtraTest, InsertSameKeyUpdatesValue) {
    AccountLruMap<4> m;
    auto a1 = MakeAddr("key1");
    a1->set_balance(100);
    m.insert(a1);
    auto a2 = MakeAddr("key1");
    a2->set_balance(200);
    m.insert(a2);
    // After second insert, get should return the updated value
    auto got = m.get("key1");
    ASSERT_NE(nullptr, got);
    EXPECT_EQ(200u, got->balance());
}

TEST(AccountLruMapExtraTest, InsertEvictsLeastRecentlyUsed) {
    AccountLruMap<2> m;  // capacity 2
    m.insert(MakeAddr("a"));
    m.insert(MakeAddr("b"));
    m.insert(MakeAddr("c"));  // evicts "a"
    EXPECT_EQ(nullptr, m.get("a"));
    EXPECT_NE(nullptr, m.get("b"));
    EXPECT_NE(nullptr, m.get("c"));
}

TEST(AccountLruMapExtraTest, GetMissReturnsNullptr) {
    AccountLruMap<4> m;
    EXPECT_EQ(nullptr, m.get("nonexistent_key"));
}

// ---- AccountLruMap::get_or_insert branches ----

TEST(AccountLruMapExtraTest, GetOrInsertExistingReturnsOld) {
    AccountLruMap<4> m;
    auto original = MakeAddr("k1");
    original->set_balance(111);
    m.insert(original);

    auto newer = MakeAddr("k1");
    newer->set_balance(999);
    auto result = m.get_or_insert("k1", newer);
    EXPECT_EQ(111u, result->balance());
}

TEST(AccountLruMapExtraTest, GetOrInsertNewKeyInserts) {
    AccountLruMap<4> m;
    auto v = MakeAddr("newkey");
    v->set_balance(42);
    auto result = m.get_or_insert("newkey", v);
    EXPECT_EQ(42u, result->balance());
    EXPECT_NE(nullptr, m.get("newkey"));
}

TEST(AccountLruMapExtraTest, GetOrInsertEvictsWhenFull) {
    AccountLruMap<2> m;  // capacity 2
    m.insert(MakeAddr("x"));
    m.insert(MakeAddr("y"));
    // get_or_insert a new key → triggers eviction
    auto v = MakeAddr("z");
    auto result = m.get_or_insert("z", v);
    EXPECT_NE(nullptr, result);
    // "x" should have been evicted
    EXPECT_EQ(nullptr, m.get("x"));
}

// ---- isContractCreateToTxMessageItem ----

TEST(BlockUtilsExtraTest, IsContractCreateTxItemWithLibraryBytes) {
    pools::protobuf::ToTxMessageItem item;
    item.set_library_bytes("some_bytecode");
    EXPECT_TRUE(isContractCreateToTxMessageItem(item));
}

TEST(BlockUtilsExtraTest, IsContractCreateTxItemWithoutLibraryBytes) {
    pools::protobuf::ToTxMessageItem item;
    EXPECT_FALSE(isContractCreateToTxMessageItem(item));
}

// ---- BlockTxsItem construction and field defaults ----

TEST(BlockTxsItemExtraTest, DefaultConstruction) {
    BlockTxsItem item;
    EXPECT_EQ(nullptr, item.tx_ptr);
    EXPECT_EQ(0u, item.tx_count);
    EXPECT_FALSE(item.success);
    EXPECT_EQ(-1, item.leader_to_index);
}

// ---- BlockErrorCode and AddressType constants ----

TEST(BlockUtilsExtraTest, ErrorCodeOrdering) {
    EXPECT_LT(kBlockSuccess, kBlockError);
    EXPECT_LT(kBlockError, kBlockDbNotExists);
    EXPECT_LT(kBlockDbNotExists, kBlockDbDataInvalid);
    EXPECT_LT(kBlockDbDataInvalid, kBlockAddressNotExists);
}

TEST(BlockUtilsExtraTest, AddressTypeConstants) {
    EXPECT_EQ(0, kNormalAddress);
    EXPECT_EQ(1, kContractAddress);
    EXPECT_NE(kNormalAddress, kContractAddress);
}

}  // namespace test
}  // namespace block
}  // namespace seth
