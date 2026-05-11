#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <string>

#include "common/encode.h"
#include "common/hash.h"
#include "contract/call_parameters.h"
#include "contract/contract_ripemd160.h"
#include "contract/contract_sha256.h"
#include "contract/contract_utils.h"

namespace seth {
namespace contract {
namespace test {

// ---- ContractSha256 ---------------------------------------------------------

TEST(ContractSha256Branches, EmptyDataReturnsError) {
    ContractSha256 cc(kContractSha256);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(cc.call(params, 0, "", res), kContractError);
}

TEST(ContractSha256Branches, InsufficientGasReturnsError) {
    ContractSha256 cc(kContractSha256);
    CallParameters params;
    params.data = "a";  // ComputeGasUsed(60, 12, 1) == 60 + 12 == 72

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 71;

    EXPECT_EQ(cc.call(params, 0, "", res), kContractError);
}

TEST(ContractSha256Branches, SuccessHashesInput) {
    ContractSha256 cc(kContractSha256);
    CallParameters params;
    params.data = "hello";

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 100'000;

    EXPECT_EQ(cc.call(params, 0, "", res), kContractSuccess);

    const uint64_t gas_used =
        60 + (static_cast<uint32_t>(params.data.size()) + 31) / 32 * 12;
    EXPECT_EQ(static_cast<uint64_t>(res->gas_left), 100'000 - gas_used);

    const std::string expect_bin = common::Hash::Sha256(params.data);
    ASSERT_EQ(res->output_size, expect_bin.size());
    std::string got(reinterpret_cast<const char*>(res->output_data), res->output_size);
    EXPECT_EQ(got, expect_bin);

    delete[] res->output_data;
    res->output_data = nullptr;
    res->output_size = 0;
}

// ---- Ripemd160 -------------------------------------------------------------

TEST(Ripemd160Branches, InsufficientGasReturnsErrorOnEmptyInput) {
    // empty input still consumes base gas (600 + 0 words)
    Ripemd160 ripe(kContractRipemd160);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 599;

    EXPECT_EQ(ripe.call(params, 0, "", res), kContractError);
}

TEST(Ripemd160Branches, EmptyInputProducesPaddedEthereumOutput) {
    Ripemd160 ripe(kContractRipemd160);
    CallParameters params;
    params.data.clear();

    constexpr int64_t kGas = 1'000'000;
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = kGas;

    ASSERT_EQ(ripe.call(params, 0, "", res), kContractSuccess);

    constexpr uint64_t kBaseGasWord = 600;
    ASSERT_EQ(static_cast<uint64_t>(res->gas_left), kGas - static_cast<int64_t>(kBaseGasWord));

    ASSERT_EQ(res->output_size, 32u);
    const std::string expect = common::Encode::HexDecode(
        "0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31");
    std::string got(reinterpret_cast<const char*>(res->output_data), res->output_size);
    EXPECT_EQ(got, expect);

    delete[] res->output_data;
    res->output_data = nullptr;
    res->output_size = 0;
}

TEST(Ripemd160Branches, SuccessWithNonEmptyInput) {
    Ripemd160 ripe(kContractRipemd160);
    CallParameters params;
    params.data = "bitcoin";

    constexpr int64_t kGas = 1'000'000;
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = kGas;

    ASSERT_EQ(ripe.call(params, 0, "", res), kContractSuccess);

    const uint64_t gas_used =
        600 + (static_cast<uint32_t>(params.data.size()) + 31) / 32 * 120;
    ASSERT_EQ(static_cast<uint64_t>(res->gas_left), kGas - static_cast<int64_t>(gas_used));

    ASSERT_EQ(res->output_size, 32u);
    const std::string expect = common::Encode::HexDecode(
        "0000000000000000000000005891bf40b0b0e8e19f524bdc2e842d012264624b");
    std::string got(reinterpret_cast<const char*>(res->output_data), res->output_size);
    EXPECT_EQ(got, expect);

    delete[] res->output_data;
    res->output_data = nullptr;
    res->output_size = 0;
}

}  // namespace test
}  // namespace contract
}  // namespace seth
