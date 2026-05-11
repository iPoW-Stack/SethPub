#include <evmc/evmc.hpp>
#include <gtest/gtest.h>

#include <string>

#include "common/encode.h"
#include "contract/call_parameters.h"
#include "contract/contract_alt_bn128_G1_add.h"
#include "contract/contract_alt_bn128_G1_mul.h"
#include "contract/contract_alt_bn128_pairing_product.h"
#include "contract/contract_utils.h"

namespace seth {
namespace contract {
namespace test {

// ---------- G1 add (fixed gas 150) -------------------------------------------

TEST(AltBn128G1AddBranches, EmptyInput) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 10'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, InsufficientGas) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data = "x";

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 149;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, InvalidCurveInput) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data.assign(32, '\xff');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, InvalidCurveInputWithCorrectLength) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    // Keep EIP-196 length valid (128) but force invalid coordinates.
    params.data.assign(128, '\xff');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, CanonicalButNonCurvePointsFailInEngine) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    // 4 coordinates with byte value 0x01:
    // - Canonical (< q), so field-bound check passes.
    // - Not guaranteed to be on curve, so alt_bn128 add should fail.
    params.data.assign(128, '\x01');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, SecondPointInvalidCanonicalCheckFails) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data.assign(128, '\x00');
    // Keep the first point canonical (all zero), but make second point x
    // clearly invalid (> q) so the second ValidateG1EncodedPoint path is hit.
    for (size_t i = 64; i < 96; ++i) {
        params.data[i] = static_cast<char>(0xff);
    }

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, FirstPointYInvalidCanonicalCheckFails) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data.assign(128, '\x00');
    // First point x is canonical zero, but y is intentionally > q.
    for (size_t i = 32; i < 64; ++i) {
        params.data[i] = static_cast<char>(0xff);
    }

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, CoordinateEqualToFieldModulusIsRejected) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    // x1 equals field modulus q exactly => not strictly lower than q.
    const std::string q = common::Encode::HexDecode(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    params.data.assign(128, '\x00');
    params.data.replace(0, q.size(), q);

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;
    EXPECT_EQ(add.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, InputLengthBoundaryAround128IsRejected) {
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 500'000;

    CallParameters short_params;
    short_params.data.assign(127, '\x00');
    EXPECT_EQ(add.call(short_params, 0, "", res), kContractError);

    CallParameters long_params;
    long_params.data.assign(129, '\x00');
    EXPECT_EQ(add.call(long_params, 0, "", res), kContractError);
}

TEST(AltBn128G1AddBranches, SuccessVector) {
    const std::string input = common::Encode::HexDecode(
        "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9"
        "063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"
        "07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed"
        "06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7");
    const std::string expect_out = common::Encode::HexDecode(
        "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703"
        "301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915");

    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    constexpr int64_t kStart = 200'000;
    res->gas_left = kStart;

    ASSERT_EQ(add.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, kStart - 150);
    ASSERT_EQ(res->output_size, expect_out.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(res->output_data), res->output_size), expect_out);
    delete[] res->output_data;
    res->output_data = nullptr;
}

TEST(AltBn128G1AddBranches, SuccessVectorWorksAtExactGasBoundary) {
    const std::string input = common::Encode::HexDecode(
        "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9"
        "063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"
        "07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed"
        "06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7");
    ContractAltBn128G1Add add(kContractAlt_bn128_G1_add);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 150;  // exactly gas_cast_

    ASSERT_EQ(add.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, 0);
    delete[] res->output_data;
    res->output_data = nullptr;
}

// ---------- G1 scalar mul (fixed gas 6000) -------------------------------------------

TEST(AltBn128G1MulBranches, EmptyInput) {
    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 100'000;
    EXPECT_EQ(mul.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1MulBranches, InsufficientGas) {
    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    CallParameters params;
    params.data = std::string(96, 'q');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 5999;
    EXPECT_EQ(mul.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1MulBranches, InvalidInput) {
    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    CallParameters params;
    params.data.assign(64, '\x13');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 50'000;
    EXPECT_EQ(mul.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1MulBranches, InvalidInputWithCorrectLength) {
    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    CallParameters params;
    // Keep EIP-196 length valid (96) but force invalid point/scalar payload.
    params.data.assign(96, '\xff');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 50'000;
    EXPECT_EQ(mul.call(params, 0, "", res), kContractError);
}

TEST(AltBn128G1MulBranches, InputLengthBoundaryAround96IsRejected) {
    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 100'000;

    CallParameters short_params;
    short_params.data.assign(95, '\x00');
    EXPECT_EQ(mul.call(short_params, 0, "", res), kContractError);

    CallParameters long_params;
    long_params.data.assign(97, '\x00');
    EXPECT_EQ(mul.call(long_params, 0, "", res), kContractError);
}

TEST(AltBn128G1MulBranches, SuccessVector) {
    const std::string input = common::Encode::HexDecode(
        "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7"
        "21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204"
        "00000000000000000000000000000000000000000000000011138ce750fa15c2");
    const std::string expect_out = common::Encode::HexDecode(
        "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c"
        "031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc");

    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    constexpr int64_t kStart = 200'000;
    res->gas_left = kStart;

    ASSERT_EQ(mul.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, kStart - 6000);
    ASSERT_EQ(res->output_size, expect_out.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(res->output_data), res->output_size), expect_out);
    delete[] res->output_data;
    res->output_data = nullptr;
}

TEST(AltBn128G1MulBranches, SuccessVectorWorksAtExactGasBoundary) {
    const std::string input = common::Encode::HexDecode(
        "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7"
        "21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204"
        "00000000000000000000000000000000000000000000000011138ce750fa15c2");
    ContractAltBn128G1Mul mul(kContractAlt_bn128_G1_mul);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 6000;  // exact gas required

    ASSERT_EQ(mul.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, 0);
    delete[] res->output_data;
    res->output_data = nullptr;
}

// ---------- Pairing product (gas = 45000 + len * 34000) ----------------------

namespace {

const char kPairingValidHex[] =
    "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
    "3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
    "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"
    "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"
    "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"
    "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
    "111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c"
    "2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

}  // namespace

TEST(AltBn128PairingBranches, EmptyInput) {
    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    CallParameters params;
    params.data.clear();

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 5'000'000;
    EXPECT_EQ(pairing.call(params, 0, "", res), kContractError);
}

TEST(AltBn128PairingBranches, InsufficientGas) {
    const std::string input = common::Encode::HexDecode(kPairingValidHex);
    const int64_t need = static_cast<int64_t>(45000 + input.size() * 34000);

    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = need - 1;
    EXPECT_EQ(pairing.call(params, 0, "", res), kContractError);
}

TEST(AltBn128PairingBranches, InvalidInput) {
    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    CallParameters params;
    params.data = std::string(128, '\xab');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 5'000'000;
    EXPECT_EQ(pairing.call(params, 0, "", res), kContractError);
}

TEST(AltBn128PairingBranches, InvalidInputWithCorrectPairStride) {
    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    CallParameters params;
    // One pair stride (192 bytes), but invalid curve coordinates.
    params.data.assign(192, '\xff');

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 10'000'000;
    EXPECT_EQ(pairing.call(params, 0, "", res), kContractError);
}

TEST(AltBn128PairingBranches, LengthBoundaryAround192StrideRejected) {
    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = 10'000'000;

    CallParameters short_params;
    short_params.data.assign(191, '\x00');
    EXPECT_EQ(pairing.call(short_params, 0, "", res), kContractError);

    CallParameters long_params;
    long_params.data.assign(193, '\x00');
    EXPECT_EQ(pairing.call(long_params, 0, "", res), kContractError);
}

TEST(AltBn128PairingBranches, SuccessVector) {
    const std::string input = common::Encode::HexDecode(kPairingValidHex);
    const std::string expect_one = common::Encode::HexDecode(
        "0000000000000000000000000000000000000000000000000000000000000001");
    const int64_t gas_need = static_cast<int64_t>(45000 + input.size() * 34000);

    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    const int64_t kStart = gas_need + 100'000;
    res->gas_left = kStart;

    ASSERT_EQ(pairing.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, kStart - gas_need);
    ASSERT_EQ(res->output_size, expect_one.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(res->output_data), res->output_size), expect_one);

    delete[] res->output_data;
    res->output_data = nullptr;
}

TEST(AltBn128PairingBranches, SuccessVectorWorksAtExactGasBoundary) {
    const std::string input = common::Encode::HexDecode(kPairingValidHex);
    const int64_t gas_need = static_cast<int64_t>(45000 + input.size() * 34000);

    ContractaltBn128PairingProduct pairing(kContractAlt_bn128_pairing_product);
    CallParameters params;
    params.data = input;

    evmc_result call_result = {};
    evmc::Result evmc_res{ call_result };
    evmc_result* res = reinterpret_cast<evmc_result*>(&evmc_res);
    res->gas_left = gas_need;

    ASSERT_EQ(pairing.call(params, 0, "", res), kContractSuccess);
    EXPECT_EQ(res->gas_left, 0);
    delete[] res->output_data;
    res->output_data = nullptr;
}

}  // namespace test
}  // namespace contract
}  // namespace seth
