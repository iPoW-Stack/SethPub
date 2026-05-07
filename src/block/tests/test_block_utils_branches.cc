#include <gtest/gtest.h>

#include <string>

#include "common/encode.h"
#include "protos/pools.pb.h"

#include "block/block_utils.h"

namespace seth {
namespace block {
namespace test {

TEST(BlockUtilsBranches, IsContractCreateToTxReflectsLibraryBytes) {
    pools::protobuf::ToTxMessageItem item;
    EXPECT_FALSE(isContractCreateToTxMessageItem(item));

    item.set_library_bytes("initcode");
    EXPECT_TRUE(isContractCreateToTxMessageItem(item));

    item.clear_library_bytes();
    EXPECT_FALSE(isContractCreateToTxMessageItem(item));
}

TEST(BlockUtilsBranches, GenesisNetworkAccountMatchesHexDecode) {
    const char* hex = "b5be6f0090e4f5d40458258ed9adf843324c0327145c48b55091f33673d2d5a4";
    std::string expected = common::Encode::HexDecode(std::string(hex));
    EXPECT_EQ(kCreateGenesisNetwrokAccount, expected);
    EXPECT_EQ(kCreateGenesisNetwrokAccount.size(), 32u);
}

TEST(BlockUtilsBranches, ConstantsSanityFromBlockUtils) {
    EXPECT_EQ(static_cast<uint32_t>(kNormalAddress), 0u);
    EXPECT_EQ(static_cast<uint32_t>(kContractAddress), 1u);
    EXPECT_EQ(kStopConsensusTimeoutMs, 30000llu);
}

TEST(BlockUtilsBranches, BlockErrorCodeEnumComplete) {
    EXPECT_EQ(kBlockSuccess, 0);
    EXPECT_EQ(kBlockError, 1);
    EXPECT_EQ(kBlockDbNotExists, 2);
    EXPECT_EQ(kBlockDbDataInvalid, 3);
    EXPECT_EQ(kBlockAddressNotExists, 4);
    EXPECT_EQ(kBlockVerifyAggSignFailed, 5);
}

TEST(BlockUtilsBranches, LeaderWithStatisticTxItemDefaults) {
    LeaderWithStatisticTxItem item;
    EXPECT_EQ(item.elect_height, 0u);
    EXPECT_EQ(item.leader_idx, common::kInvalidUint32);
    EXPECT_EQ(item.leader_to_index, -1);
    EXPECT_EQ(item.shard_statistic_tx, nullptr);
    EXPECT_EQ(item.cross_statistic_tx, nullptr);
}

TEST(BlockUtilsBranches, HeightItemStoresHeightAndHash) {
    HeightItem a{100ull, "abc"};
    HeightItem b{100ull, "abc"};
    HeightItem c{101ull, "abc"};
    EXPECT_EQ(a.height, b.height);
    EXPECT_EQ(a.hash, b.hash);
    EXPECT_NE(a.height, c.height);
}

TEST(BlockUtilsBranches, AddressTypeEnumDistinct) {
    EXPECT_NE(static_cast<int>(kNormalAddress), static_cast<int>(kContractAddress));
}

TEST(BlockUtilsBranches, BlockTxsItemDefaultsAndTimeoutWindow) {
    const uint64_t before = common::TimeUtils::TimestampMs();
    BlockTxsItem item;
    const uint64_t after = common::TimeUtils::TimestampMs();
    EXPECT_EQ(item.tx_ptr, nullptr);
    EXPECT_EQ(item.tx_count, 0u);
    EXPECT_FALSE(item.success);
    EXPECT_EQ(item.leader_to_index, -1);
    EXPECT_GE(item.stop_consensus_timeout, before + kStopConsensusTimeoutMs);
    EXPECT_LE(item.stop_consensus_timeout, after + kStopConsensusTimeoutMs + 5u);
}

TEST(BlockUtilsBranches, BlockToDbItemKeepsPointersFromCtor) {
    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    auto batch = std::make_shared<db::DbWriteBatch>();
    BlockToDbItem item(vb, batch);
    EXPECT_EQ(item.view_block_ptr, vb);
    EXPECT_EQ(item.final_db_batch, batch);
}

TEST(BlockUtilsBranches, LocalToTxInfoConstructorStoresAllFields) {
    localToTxInfo info("dest_addr", 123ull, 7u, "lib_bytes");
    EXPECT_EQ(info.des, "dest_addr");
    EXPECT_EQ(info.amount, 123ull);
    EXPECT_EQ(info.pool_index, 7u);
    EXPECT_EQ(info.library_bytes, "lib_bytes");
}

}  // namespace test
}  // namespace block
}  // namespace seth
