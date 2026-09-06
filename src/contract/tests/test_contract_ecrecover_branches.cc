#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "common/encode.h"
#include "contract/call_parameters.h"
#include "contract/contract_ecrecover.h"
#include "contract/contract_utils.h"
#include "security/ecdsa/ecdsa.h"
#include "security/security.h"

namespace shardora {
namespace contract {
namespace test {

TEST(EcrecoverBranches, RejectsLowParamGas) {
    std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
    Ecrecover recover(kContractEcrecover, sec);

    CallParameters params;
    params.data.assign(128, '\xaa');
    params.gas = 2999u;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(recover.call(params, 0, "", res), kContractError);
}

TEST(EcrecoverBranches, RejectsWrongDataLength) {
    std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
    Ecrecover recover(kContractEcrecover, sec);

    CallParameters params;
    params.data.assign(127, '\xbb');
    params.gas = 500'000;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 1'000'000;

    EXPECT_EQ(recover.call(params, 0, "", res), kContractError);
}

TEST(EcrecoverBranches, ExactMinimumParamGasSucceeds) {
    std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
    Ecrecover recover(kContractEcrecover, sec);

    CallParameters params;
    params.data = common::Encode::HexDecode(
        "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e"
        "000000000000000000000000000000000000000000000000000000000000001b"
        "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e"
        "789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02");
    ASSERT_EQ(params.data.size(), 128u);
    params.gas = 3000u;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    constexpr int64_t kLeft = 500'000;
    res->gas_left = kLeft;

    ASSERT_EQ(recover.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, kLeft - 3000);

    security::Ecdsa verify;
    const std::string output(reinterpret_cast<const char*>(res->output_data), res->output_size);
    EXPECT_EQ(verify.UnicastAddress(output),
        common::Encode::HexDecode("ceaccac640adf55b2028469bd36ba501f28b699d"));

    delete[] res->output_data;
    res->output_data = nullptr;
}

}  // namespace test
}  // namespace contract
}  // namespace shardora
