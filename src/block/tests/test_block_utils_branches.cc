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

}  // namespace test
}  // namespace block
}  // namespace seth
