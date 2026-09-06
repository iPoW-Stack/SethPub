#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "common/global_info.h"
#include "common/utils.h"
#include "network/network_utils.h"
#include "pools/tx_utils.h"

namespace shardora {
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

TEST(PoolsTxUtilsBranches, PoolsErrorCodeEnumValues) {
    EXPECT_EQ(kPoolsSuccess, 0);
    EXPECT_EQ(kPoolsError, 1);
    EXPECT_EQ(kPoolsTxAdded, 2);
}

TEST(PoolsTxUtilsBranches, PoolsCountPrioItemTieNeitherLess) {
    PoolsCountPrioItem a(0u, 7u);
    PoolsCountPrioItem b(9u, 7u);
    EXPECT_FALSE(a < b);
    EXPECT_FALSE(b < a);
}

TEST(PoolsTxUtilsBranches, PoolsTmPrioItemTieNeitherLess) {
    PoolsTmPrioItem a(0u, 500ull);
    PoolsTmPrioItem b(3u, 500ull);
    EXPECT_FALSE(a < b);
    EXPECT_FALSE(b < a);
}

TEST(PoolsTxUtilsBranches, CrossStatisticItemConstructors) {
    CrossStatisticItem x;
    EXPECT_EQ(x.des_net, 0u);
    CrossStatisticItem y(77u);
    EXPECT_EQ(y.des_net, 77u);
}

TEST(PoolsTxUtilsBranches, PoolBlocksInfoDefaultLatestConsensusHeight) {
    PoolBlocksInfo info;
    EXPECT_EQ(info.latest_consensus_height_, 0u);
    EXPECT_TRUE(info.blocks.empty());
}

TEST(PoolsTxUtilsBranches, ElectNodeStatisticInfoDefaultGasTotals) {
    ElectNodeStatisticInfo info;
    EXPECT_EQ(info.all_gas_amount, 0u);
    EXPECT_EQ(info.all_gas_for_root, 0u);
}

TEST(PoolsTxUtilsBranches, StatisticInfoItemDefaultHeightsAndGas) {
    StatisticInfoItem info;
    EXPECT_EQ(info.all_gas_amount, 0u);
    EXPECT_EQ(info.root_all_gas_amount, 0u);
    EXPECT_EQ(info.statistic_min_height, 0u);
    EXPECT_EQ(info.statistic_max_height, 0u);
}

TEST(PoolsTxUtilsBranches, HeightStatisticInfoDefaultHeights) {
    HeightStatisticInfo h;
    EXPECT_EQ(h.tm_height, 0u);
    EXPECT_EQ(h.max_height, 0u);
    EXPECT_TRUE(h.elect_node_info_map.empty());
}

TEST(PoolsTxUtilsBranches, PoolStatisticItemFieldsAssignable) {
    PoolStatisticItem p{};
    p.min_height = 1u;
    p.max_height = 100u;
    EXPECT_LT(p.min_height, p.max_height);
}

TEST(PoolsTxUtilsBranches, CrossShardItemAggregateInitialization) {
    CrossShardItem x{};
    x.pool = 3u;
    x.des_shard = 9u;
    EXPECT_EQ(x.pool, 3u);
    EXPECT_EQ(x.des_shard, 9u);
}

TEST(PoolsTxUtilsBranches, InvalidGidItemDefaultScalars) {
    InvalidGidItem g;
    EXPECT_EQ(g.max_pool_index_count, 0u);
    EXPECT_EQ(g.max_pool_height_count, 0u);
    EXPECT_TRUE(g.checked_members.empty());
}

TEST(PoolsTxUtilsBranches, CrossItemRecordHashSensitiveToLargeHeight) {
    CrossItemRecordHash hasher;
    const CrossItem a{1u, 2u, 100ull};
    const CrossItem b{1u, 2u, (1ull << 48) | 999ull};
    EXPECT_NE(hasher(a), hasher(b));
}

TEST(PoolsTxUtilsBranches, IsUserTransactionRecognizesConfiguredSteps) {
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kNormalFrom));
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kCreateContract));
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kContractExcute));
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kContractGasPrefund));
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kContractRefund));
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kJoinElect));
    EXPECT_TRUE(IsUserTransaction(pools::protobuf::kCreateLibrary));

    EXPECT_FALSE(IsUserTransaction(pools::protobuf::kNormalTo));
    EXPECT_FALSE(IsUserTransaction(pools::protobuf::kConsensusRootElectShard));
    EXPECT_FALSE(IsUserTransaction(pools::protobuf::kCross));
}

TEST(PoolsTxUtilsBranches, IsTxUseFromAddressExplicitFalseAndTrueCases) {
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kNormalTo));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kRootCreateAddress));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kConsensusLocalTos));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kConsensusRootElectShard));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kConsensusRootTimeBlock));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kConsensusCreateGenesisAcount));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kContractExcute));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kContractRefund));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kStatistic));
    EXPECT_FALSE(IsTxUseFromAddress(pools::protobuf::kPoolStatisticTag));

    EXPECT_TRUE(IsTxUseFromAddress(pools::protobuf::kCreateContract));
    EXPECT_TRUE(IsTxUseFromAddress(pools::protobuf::kCreateLibrary));
    EXPECT_TRUE(IsTxUseFromAddress(pools::protobuf::kJoinElect));
    EXPECT_TRUE(IsTxUseFromAddress(pools::protobuf::kNormalFrom));
    EXPECT_TRUE(IsTxUseFromAddress(pools::protobuf::kContractGasPrefund));
}

TEST(PoolsTxUtilsBranches, IsRootNodeMatchesRootCongressAndWaitingPair) {
    auto* g = common::GlobalInfo::Instance();
    const uint32_t prev = g->network_id();
    g->set_network_id(network::kRootCongressNetworkId);
    EXPECT_TRUE(IsRootNode());
    g->set_network_id(network::kRootCongressNetworkId + network::kConsensusWaitingShardOffset);
    EXPECT_TRUE(IsRootNode());
    g->set_network_id(network::kConsensusShardBeginNetworkId);
    EXPECT_FALSE(IsRootNode());
    g->set_network_id(prev);
}

static void FillMinimalTxMessage(pools::protobuf::TxMessage* tx) {
    tx->set_nonce(7ull);
    tx->set_to(std::string(common::kUnicastAddressLength, '\x03'));
    tx->set_amount(1ull);
    tx->set_gas_limit(21000ull);
    tx->set_gas_price(2ull);
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashSm3PathWhenPubkeyLengthIs64) {
    pools::protobuf::TxMessage tx;
    FillMinimalTxMessage(&tx);
    tx.set_pubkey(std::string(64u, 'p'));
    tx.set_step(pools::protobuf::kNormalFrom);

    const std::string h = GetTxMessageHash(tx);
    EXPECT_FALSE(h.empty());
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashKeccakPathWhenPubkeyLengthNot64) {
    pools::protobuf::TxMessage tx;
    FillMinimalTxMessage(&tx);
    tx.set_pubkey(std::string(32u, 'q'));
    tx.set_step(pools::protobuf::kNormalFrom);

    const std::string h_short_pk = GetTxMessageHash(tx);

    pools::protobuf::TxMessage tx64 = tx;
    tx64.set_pubkey(std::string(64u, 'q'));
    const std::string h_64_byte_pk = GetTxMessageHash(tx64);

    EXPECT_FALSE(h_short_pk.empty());
    EXPECT_FALSE(h_64_byte_pk.empty());
    EXPECT_NE(h_short_pk, h_64_byte_pk);
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashOptionalFieldsChangeDigest) {
    pools::protobuf::TxMessage a;
    FillMinimalTxMessage(&a);
    a.set_pubkey(std::string(64u, 'r'));
    a.set_step(pools::protobuf::kNormalFrom);

    pools::protobuf::TxMessage b = a;
    b.set_contract_code("bytecode");

    EXPECT_NE(GetTxMessageHash(a), GetTxMessageHash(b));
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashDiffersWhenStepPresenceDiffers) {
    pools::protobuf::TxMessage no_step;
    FillMinimalTxMessage(&no_step);
    no_step.set_pubkey(std::string(64u, 'z'));
    no_step.clear_step();  // exercise has_step() == false branch

    pools::protobuf::TxMessage with_step = no_step;
    with_step.set_step(pools::protobuf::kNormalFrom);  // has_step() == true branch

    EXPECT_NE(GetTxMessageHash(no_step), GetTxMessageHash(with_step));
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashSameWhenStepUnsetInBothMessages) {
    pools::protobuf::TxMessage a;
    FillMinimalTxMessage(&a);
    a.set_pubkey(std::string(64u, 'y'));
    a.clear_step();

    pools::protobuf::TxMessage b = a;
    EXPECT_EQ(GetTxMessageHash(a), GetTxMessageHash(b));
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashContractInputChangesDigest) {
    pools::protobuf::TxMessage a;
    FillMinimalTxMessage(&a);
    a.set_pubkey(std::string(64u, 's'));
    a.set_step(pools::protobuf::kNormalFrom);

    pools::protobuf::TxMessage b = a;
    b.set_contract_input("input_payload");

    EXPECT_NE(GetTxMessageHash(a), GetTxMessageHash(b));
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashContractPrefundChangesDigest) {
    pools::protobuf::TxMessage a;
    FillMinimalTxMessage(&a);
    a.set_pubkey(std::string(64u, 't'));
    a.set_step(pools::protobuf::kNormalFrom);

    pools::protobuf::TxMessage b = a;
    b.set_contract_prefund(888ull);

    EXPECT_NE(GetTxMessageHash(a), GetTxMessageHash(b));
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashKeyAndValueBranches) {
    pools::protobuf::TxMessage base;
    FillMinimalTxMessage(&base);
    base.set_pubkey(std::string(64u, 'u'));
    base.set_step(pools::protobuf::kNormalFrom);

    pools::protobuf::TxMessage key_only = base;
    key_only.set_key("k");

    pools::protobuf::TxMessage key_and_value = key_only;
    key_and_value.set_value("v");

    EXPECT_NE(GetTxMessageHash(base), GetTxMessageHash(key_only));
    EXPECT_NE(GetTxMessageHash(key_only), GetTxMessageHash(key_and_value));
}

TEST(PoolsTxUtilsBranches, GetTxMessageHashValueWithoutKeyDoesNotAffectDigest) {
    pools::protobuf::TxMessage a;
    FillMinimalTxMessage(&a);
    a.set_pubkey(std::string(64u, 'w'));
    a.set_step(pools::protobuf::kNormalFrom);

    pools::protobuf::TxMessage b = a;
    b.set_value("value_only_should_be_ignored_without_key");

    // has_value() is true on b, but code only appends value inside has_key() branch.
    EXPECT_EQ(GetTxMessageHash(a), GetTxMessageHash(b));
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
