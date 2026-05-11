#include <cstring>

#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <string>

#include "contract/call_parameters.h"
#include "contract/contract_create2.h"
#include "contract/contract_utils.h"

namespace seth {
namespace contract {
namespace test {

TEST(ContractCreate2Branches, RejectsInputShorterThan32Bytes) {
    ContractCreate2 cc(kContractCreate2);
    CallParameters params;
    memset(&params.create2_salt, 0, sizeof(params.create2_salt));
    params.from.assign(20, '\x02');
    params.data.assign(31, '\xaa');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;

    EXPECT_EQ(cc.call(params, 0, "", res), kContractError);
}

TEST(ContractCreate2Branches, RejectsWhenGasBelowEip1014Cost) {
    ContractCreate2 cc(kContractCreate2);
    CallParameters params;
    memset(&params.create2_salt, 0, sizeof(params.create2_salt));
    params.from.assign(20, '\x03');
    params.data.assign(32, '\x00');

    // word_count = (32 + 31) / 32 = 1  -> 32000 + 6 * 1 = 32006
    constexpr int64_t kRequired = 32006;
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = kRequired - 1;

    EXPECT_EQ(cc.call(params, 0, "", res), kContractError);
}

TEST(ContractCreate2Branches, AcceptsExactMinimumGas) {
    ContractCreate2 cc(kContractCreate2);
    CallParameters params;
    memset(&params.create2_salt, 0, sizeof(params.create2_salt));
    params.from.assign(20, '\x04');
    params.data.assign(32, '\x00');

    constexpr int64_t kRequired = 32006;
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = kRequired;

    ASSERT_EQ(cc.call(params, 0, "", res), kContractSuccess);
    ASSERT_EQ(res->gas_left, 0);
    ASSERT_EQ(res->output_size, 32u);

    delete[] res->output_data;
    res->output_data = nullptr;
    res->output_size = 0;
}

TEST(ContractCreate2Branches, OutputMatchesImplicitlyPaddedShortSender) {
    const std::string init_code(32, '\xff');

    ContractCreate2 cc_a(kContractCreate2);
    CallParameters short_from;
    memset(&short_from.create2_salt, 0, sizeof(short_from.create2_salt));
    short_from.from = std::string("\xab\xcd\xef", 3);
    short_from.data = init_code;

    evmc_result cr_a = {};
    evmc::Result wr_a{ cr_a };
    evmc_result* res_a = reinterpret_cast<evmc_result*>(&wr_a);
    res_a->gas_left = 1'000'000;
    ASSERT_EQ(cc_a.call(short_from, 0, "", res_a), kContractSuccess);
    std::string out_a(reinterpret_cast<const char*>(res_a->output_data), res_a->output_size);
    delete[] res_a->output_data;
    res_a->output_data = nullptr;

    ContractCreate2 cc_b(kContractCreate2);
    CallParameters padded_from;
    memset(&padded_from.create2_salt, 0, sizeof(padded_from.create2_salt));
    padded_from.from = std::string(17, '\x00') + short_from.from;
    padded_from.data = init_code;

    evmc_result cr_b = {};
    evmc::Result wr_b{ cr_b };
    evmc_result* res_b = reinterpret_cast<evmc_result*>(&wr_b);
    res_b->gas_left = 1'000'000;
    ASSERT_EQ(cc_b.call(padded_from, 0, "", res_b), kContractSuccess);
    std::string out_b(reinterpret_cast<const char*>(res_b->output_data), res_b->output_size);
    delete[] res_b->output_data;

    EXPECT_EQ(out_a, out_b);
}

TEST(ContractCreate2Branches, IdenticalCallsProduceIdenticalAddress) {
    ContractCreate2 cc(kContractCreate2);
    CallParameters params;
    memset(&params.create2_salt, 0, sizeof(params.create2_salt));
    for (size_t i = 0; i < sizeof(params.create2_salt.bytes); ++i) {
        params.create2_salt.bytes[i] = static_cast<uint8_t>(i);
    }
    params.from = std::string("\x01\x23\x45\x67\x89\xab\xcd\xef"
                              "\xfe\xdc\xba\x98\x76\x54\x32\x10"
                              "\xaa\xbb\xcc\xdd", 20);
    params.data.assign(64, '\x42');

    auto run_once = [&]() -> std::string {
        evmc_result call_result = {};
        evmc::Result evmc_res{ call_result };
        evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
        res->gas_left = 2'000'000;
        EXPECT_EQ(cc.call(params, 0, "", res), kContractSuccess);
        std::string out(reinterpret_cast<const char*>(res->output_data), res->output_size);
        delete[] res->output_data;
        res->output_data = nullptr;
        return out;
    };

    const std::string first = run_once();
    const std::string second = run_once();
    EXPECT_EQ(first, second);
    EXPECT_EQ(first.size(), 32u);
}

}  // namespace test
}  // namespace contract
}  // namespace seth
