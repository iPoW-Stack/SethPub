#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "contract/call_parameters.h"
#include "contract/contract_manager.h"
#include "contract/contract_utils.h"
#include "security/ecdsa/ecdsa.h"
#include "security/security.h"

namespace seth {
namespace contract {
namespace test {

TEST(ContractManagerBranches, CallBeforeInitReturnsNotExists) {
    ContractManager mgr;
    CallParameters params;
    params.code_address = kContractIdentity;
    params.data = "ping";
    params.gas = 1'000'000;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(mgr.call(params, 0, "", res), kContractNotExists);
}

TEST(ContractManagerBranches, UnknownCodeAddressAfterInitReturnsNotExists) {
    std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
    ContractManager mgr;
    mgr.Init(sec);

    CallParameters params;
    params.code_address.assign(20, '\xff');
    params.data = "x";
    params.gas = 1'000'000;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(mgr.call(params, 0, "", res), kContractNotExists);
}

TEST(ContractManagerBranches, RoutesToRegisteredPrecompile) {
    std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
    ContractManager mgr;
    mgr.Init(sec);

    CallParameters params;
    params.code_address = kContractIdentity;
    params.data = "echo";
    params.gas = 1'000'000;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    ASSERT_EQ(mgr.call(params, 0, "", res), kContractSuccess);
    ASSERT_EQ(res->output_size, 4u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(res->output_data), res->output_size), "echo");
    delete[] res->output_data;
    res->output_data = nullptr;
}

}  // namespace test
}  // namespace contract
}  // namespace seth
