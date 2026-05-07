#include <gtest/gtest.h>

#include "sethvm/sethvm_utils.h"

namespace seth {
namespace sethvm {
namespace test {

TEST(SethvmUtilsBranches, IsContractBytesCodeDetectsPinnedPrefix) {
    std::string good = kContractHead;
    good.push_back(static_cast<char>(0xfe));
    EXPECT_TRUE(IsContractBytesCode(good));

    // memcmp length is kContractHead.size(); inputs must be at least that long (implementation requirement).
    ASSERT_EQ(kContractHead.size(), 4u);
    EXPECT_FALSE(IsContractBytesCode(std::string(4u, '\0')));
    std::string wrong = kContractHead;
    wrong[0] = static_cast<char>(0x01);
    EXPECT_FALSE(IsContractBytesCode(wrong));
}

TEST(SethvmUtilsBranches, Uint64EvmcBytes32RoundTrip) {
    auto check = [](uint64_t v) {
        evmc_bytes32 b{};
        Uint64ToEvmcBytes32(b, v);
        EXPECT_EQ(EvmcBytes32ToUint64(b), v);
    };
    check(0ull);
    check(1ull);
    check(0xDEADBEEFCAFEBABEull);
}

TEST(SethvmUtilsBranches, ContractCallModeEnums) {
    EXPECT_EQ(static_cast<int>(kJustCall), 0);
    EXPECT_EQ(static_cast<int>(kCreate2), 3);
    EXPECT_GE(kContractCallMaxDepth, 256u);
}

}  // namespace test
}  // namespace sethvm
}  // namespace seth
