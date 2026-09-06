#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <string>

#include "contract/call_parameters.h"
#include "contract/contract_identity.h"
#include "contract/contract_utils.h"

namespace shardora {
namespace contract {
namespace test {

TEST(ContractIdentityBranches, EmptyDataReturnsError) {
    Identity identity(kContractIdentity);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(identity.call(params, 0, "", res), kContractError);
}

TEST(ContractIdentityBranches, InsufficientGasReturnsError) {
    Identity identity(kContractIdentity);
    CallParameters params;
    params.data = "a";  // ComputeGasUsed(15, 3, 1) == 15 + 3 == 18

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 17;

    EXPECT_EQ(identity.call(params, 0, "", res), kContractError);
}

TEST(ContractIdentityBranches, SuccessCopiesDataAndDeductsGas) {
    Identity identity(kContractIdentity);
    CallParameters params;
    params.data = "hello";

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    constexpr int64_t kStartGas = 1'000'000;
    res->gas_left = kStartGas;

    EXPECT_EQ(identity.call(params, 0, "", res), kContractSuccess);

    const uint64_t gas_used = 15 + (static_cast<uint32_t>(params.data.size()) + 31) / 32 * 3;
    EXPECT_EQ(static_cast<uint64_t>(res->gas_left), static_cast<uint64_t>(kStartGas - gas_used));

    ASSERT_EQ(res->output_size, params.data.size());
    const std::string out(
        reinterpret_cast<const char*>(res->output_data),
        res->output_size);
    EXPECT_EQ(out, params.data);

    delete[] res->output_data;
    res->output_data = nullptr;
    res->output_size = 0;
}

}  // namespace test
}  // namespace contract
}  // namespace shardora
