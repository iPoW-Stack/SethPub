#include <cassert>

#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <string>

#include "common/encode.h"
#include "contract/call_parameters.h"
#include "contract/contract_blake2_compression.h"
#include "contract/contract_modexp.h"
#include "contract/contract_utils.h"

namespace seth {
namespace contract {
namespace test {

namespace {

constexpr size_t kBlake2TotalInput = 4 + 64 + 128 + 8 + 8 + 1;

std::string Blake2PrecompileInput(uint32_t rounds_and_gas, uint8_t final_block_flag) {
    std::string d;
    d.reserve(kBlake2TotalInput);
    d.push_back(static_cast<char>((rounds_and_gas >> 24) & 0xff));
    d.push_back(static_cast<char>((rounds_and_gas >> 16) & 0xff));
    d.push_back(static_cast<char>((rounds_and_gas >> 8) & 0xff));
    d.push_back(static_cast<char>(rounds_and_gas & 0xff));
    d.append(64, '\0');
    d.append(128, '\0');
    d.append(8, '\0');
    d.append(8, '\0');
    d.push_back(static_cast<char>(final_block_flag));
    //assert(d.size() == kBlake2TotalInput);
    return d;
}

/** 32-byte big-endian length encoding of small integer @p length (e.g. 1 → …0001). */
std::string ModexpLengthBE32(uint64_t length) {
    std::string s(32, '\0');
    uint64_t tmp = length;
    for (int i = 31; i >= 0 && tmp != 0; --i) {
        s[static_cast<size_t>(i)] = static_cast<char>(tmp & 0xff);
        tmp >>= 8;
    }
    return s;
}

}  // namespace

// ---- Modexp ----------------------------------------------------------------

TEST(ModexpBranches, EmptyInput) {
    Modexp m(kContractModexp);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(m.call(params, 0, "", res), kContractError);
}

TEST(ModexpBranches, RejectsZeroBaseLengthAndZeroModLength) {
    Modexp m(kContractModexp);
    CallParameters params;
    params.data.assign(96, '\0');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(m.call(params, 0, "", res), kContractError);
}

TEST(ModexpBranches, InsufficientGasForFermatCase) {
    Modexp m(kContractModexp);
    CallParameters params;
    params.data = common::Encode::HexDecode(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "03"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1;

    EXPECT_EQ(m.call(params, 0, "", res), kContractError);
}

TEST(ModexpBranches, ModZeroShortCircuitReturnsZeroOutput) {
    // lengths 1 / 1 / 1, base=5, exp=1, mod=0  →  powm skipped, one zero output byte
    Modexp m(kContractModexp);
    CallParameters params;
    params.data = ModexpLengthBE32(1) + ModexpLengthBE32(1) + ModexpLengthBE32(1);
    params.data += std::string("\x05\x01\x00", 3);

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    ASSERT_EQ(m.call(params, 0, "", res), kContractSuccess);
    ASSERT_EQ(res->output_size, 1u);
    ASSERT_EQ(res->output_data[0], 0);
    delete[] res->output_data;
    res->output_data = nullptr;
}

// ---- Blake2 precompile (EIP-152 style input) -------------------------------

TEST(Blake2CompressionBranches, EmptyInput) {
    Blake2Compression b(kContractBlake2_compression);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(b.call(params, 0, "", res), kContractError);
}

TEST(Blake2CompressionBranches, WrongTotalSizeAfterGasCheck) {
    Blake2Compression b(kContractBlake2_compression);
    CallParameters params;
    params.data.assign(4, '\0');  // gas word 0 ⇒ passes gas check

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(b.call(params, 0, "", res), kContractError);
}

TEST(Blake2CompressionBranches, InsufficientGas) {
    Blake2Compression b(kContractBlake2_compression);
    CallParameters params;
    params.data = Blake2PrecompileInput(500'000, 0);

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 499'999;

    EXPECT_EQ(b.call(params, 0, "", res), kContractError);
}

TEST(Blake2CompressionBranches, InvalidFinalBlockFlag) {
    Blake2Compression b(kContractBlake2_compression);
    CallParameters params;
    params.data = Blake2PrecompileInput(4, 2);

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(b.call(params, 0, "", res), kContractError);
}

TEST(Blake2CompressionBranches, SuccessRounds12) {
    Blake2Compression b(kContractBlake2_compression);
    const uint32_t kRounds = 12;
    CallParameters params;
    params.data = Blake2PrecompileInput(kRounds, 0);

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    constexpr int64_t kStart = 500'000;
    res->gas_left = kStart;

    ASSERT_EQ(b.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, kStart - static_cast<int64_t>(kRounds));
    ASSERT_EQ(res->output_size, 64u);

    delete[] res->output_data;
    res->output_data = nullptr;
    res->output_size = 0;
}

TEST(Blake2CompressionBranches, SuccessFinalBlockFlagOne) {
    Blake2Compression b(kContractBlake2_compression);
    const uint32_t kRounds = 1;
    CallParameters params;
    params.data = Blake2PrecompileInput(kRounds, 1);

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 10'000;

    ASSERT_EQ(b.call(params, 0, "", res), kContractSuccess);
    delete[] res->output_data;
}

}  // namespace test
}  // namespace contract
}  // namespace seth
