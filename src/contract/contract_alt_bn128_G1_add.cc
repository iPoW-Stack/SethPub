#include "contract/contract_alt_bn128_G1_add.h"

#include <array>

#include "big_num/snark.h"
#include "big_num/libsnark.h"

namespace seth {

namespace contract {
namespace {

// alt_bn128 base field modulus q in 32-byte big-endian form.
constexpr std::array<uint8_t, 32> kAltBn128FieldModulusQ = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47
};

bool IsCanonicalFqElement(const uint8_t* be32) {
    // EIP-196 requires field elements to be strictly lower than q.
    for (size_t i = 0; i < kAltBn128FieldModulusQ.size(); ++i) {
        if (be32[i] < kAltBn128FieldModulusQ[i]) {
            return true;
        }
        if (be32[i] > kAltBn128FieldModulusQ[i]) {
            return false;
        }
    }
    return false;  // equal to q is invalid
}

bool ValidateG1EncodedPoint(const uint8_t* xy64) {
    return IsCanonicalFqElement(xy64) && IsCanonicalFqElement(xy64 + 32);
}

}  // namespace

ContractAltBn128G1Add::ContractAltBn128G1Add(const std::string& create_address)
        : ContractInterface(create_address) {}

ContractAltBn128G1Add::~ContractAltBn128G1Add() {}

int ContractAltBn128G1Add::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        return kContractError;
    }

    if (res->gas_left < gas_cast_) {
        return kContractError;
    }

    // EIP-196: two G1 points (x1,y1,x2,y2), 32 bytes each.
    constexpr size_t kEip196G1AddInputBytes = 128;
    if (param.data.size() != kEip196G1AddInputBytes) {
        return kContractError;
    }
    const auto* input = reinterpret_cast<const uint8_t*>(param.data.data());
    if (!ValidateG1EncodedPoint(input) || !ValidateG1EncodedPoint(input + 64)) {
        return kContractError;
    }

    bytesConstRef bytes_ref((byte*)param.data.c_str(), param.data.size());
    std::pair<bool, bytes> add_res = alt_bn128_G1_add(bytes_ref);
    if (!add_res.first) {
        return kContractError;
    }

    res->output_data = new uint8_t[add_res.second.size()];
    memcpy((void*)res->output_data, &add_res.second.at(0), add_res.second.size());
    res->output_size = add_res.second.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_cast_;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace seth
