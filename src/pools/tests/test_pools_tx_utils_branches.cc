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

}  // namespace test
}  // namespace pools
}  // namespace seth
