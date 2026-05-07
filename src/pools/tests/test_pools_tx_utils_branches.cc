#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "common/utils.h"
#include "pools/tx_utils.h"

namespace seth {
namespace pools {
namespace test {

TEST(PoolsTxUtilsBranches, GetTxKeyRoundTripUnicastAddress) {
    std::string addr(common::kUnicastAddressLength, 'A');
    const uint64_t nonce = 0xDEADBEEFCAFEBABEull;
    std::string key = GetTxKey(addr, nonce);

    ASSERT_EQ(key.size(), addr.size() + sizeof(uint64_t));
    EXPECT_EQ(std::memcmp(key.data(), addr.data(), addr.size()), 0);

    uint64_t read_nonce = 0;
    std::memcpy(&read_nonce, key.data() + addr.size(), sizeof(read_nonce));
    EXPECT_EQ(read_nonce, nonce);
}

TEST(PoolsTxUtilsBranches, GetTxKeyRoundTripPrepaymentAddressLength) {
    std::string addr(common::kPreypamentAddressLength, 'B');
    const uint64_t nonce = 12345ull;
    std::string key = GetTxKey(addr, nonce);

    ASSERT_EQ(key.size(), addr.size() + sizeof(uint64_t));
    uint64_t read_nonce = 0;
    std::memcpy(&read_nonce, key.data() + addr.size(), sizeof(read_nonce));
    EXPECT_EQ(read_nonce, nonce);
}

TEST(PoolsTxUtilsBranches, StatisticElectItemClearResetsState) {
    StatisticElectItem item;
    item.elect_height = 99u;
    item.succ_tx_count[0] = 5u;
    item.leader_lof_map[1] = nullptr;

    item.Clear();
    EXPECT_EQ(item.elect_height, 0u);
    EXPECT_EQ(item.succ_tx_count[0], 0u);
    EXPECT_TRUE(item.leader_lof_map.empty());
}

TEST(PoolsTxUtilsBranches, StatisticItemClearResetsChildren) {
    StatisticItem stats;
    stats.elect_items[0]->elect_height = 7u;
    stats.all_tx_count = 100u;
    stats.tmblock_height = 42u;
    stats.added_height.insert(1ull);

    stats.Clear();
    EXPECT_EQ(stats.elect_items[0]->elect_height, 0u);
    EXPECT_EQ(stats.all_tx_count, 0u);
    EXPECT_EQ(stats.tmblock_height, 0u);
    EXPECT_TRUE(stats.added_height.empty());
}

TEST(PoolsTxUtilsBranches, PoolsCountPrioItemLessPrefersHigherCount) {
    // operator<(other) returns true when other.count < this.count (max-heap style).
    PoolsCountPrioItem low(0u, 5u);
    PoolsCountPrioItem high(1u, 10u);
    EXPECT_FALSE(low < high);
    EXPECT_TRUE(high < low);
}

TEST(PoolsTxUtilsBranches, PoolsTmPrioItemLessComparesTimestamp) {
    PoolsTmPrioItem early(0u, 100ull);
    PoolsTmPrioItem late(1u, 200ull);
    EXPECT_TRUE(early < late);
    EXPECT_FALSE(late < early);
}

TEST(PoolsTxUtilsBranches, CrossItemEquality) {
    CrossItem x{3u, 9u, 100ull};
    CrossItem y{3u, 9u, 100ull};
    CrossItem z{3u, 9u, 101ull};
    EXPECT_TRUE(x == y);
    EXPECT_FALSE(x == z);
}

TEST(PoolsTxUtilsBranches, CrossItemRecordHashDeterministic) {
    CrossItem item{2u, 8u, 500ull};
    CrossItemRecordHash hasher;
    EXPECT_EQ(hasher(item), hasher(item));
}

TEST(PoolsTxUtilsBranches, GetTxKeyDiffersWhenNonceDiffers) {
    std::string addr(common::kUnicastAddressLength, 'C');
    const std::string k1 = GetTxKey(addr, 1ull);
    const std::string k2 = GetTxKey(addr, 2ull);
    EXPECT_NE(k1, k2);
    EXPECT_EQ(k1.size(), k2.size());
}

TEST(PoolsTxUtilsBranches, GetTxKeyDiffersWhenAddressDiffers) {
    std::string addr_a(common::kUnicastAddressLength, 'D');
    std::string addr_b(common::kUnicastAddressLength, 'E');
    const uint64_t nonce = 99ull;
    EXPECT_NE(GetTxKey(addr_a, nonce), GetTxKey(addr_b, nonce));
}

TEST(PoolsTxUtilsBranches, CrossItemRecordHashDiffersAcrossItems) {
    CrossItemRecordHash hasher;
    const CrossItem a{1u, 2u, 100ull};
    const CrossItem b{7u, 2u, 100ull};
    EXPECT_NE(hasher(a), hasher(b));
}

TEST(PoolsTxUtilsBranches, CrossItemRecordHashDiffersOnMiddleField) {
    CrossItemRecordHash hasher;
    const CrossItem a{4u, 1u, 50ull};
    const CrossItem b{4u, 2u, 50ull};
    EXPECT_NE(hasher(a), hasher(b));
}

TEST(PoolsTxUtilsBranches, CrossItemRecordHashDiffersOnAmountField) {
    CrossItemRecordHash hasher;
    const CrossItem a{4u, 5u, 50ull};
    const CrossItem b{4u, 5u, 51ull};
    EXPECT_NE(hasher(a), hasher(b));
}

}  // namespace test
}  // namespace pools
}  // namespace seth
