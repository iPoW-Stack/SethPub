#include "contract/contract_alt_bn128_pairing_product.h"

#include <array>

#include "big_num/snark.h"
#include "big_num/libsnark.h"

namespace seth {

namespace contract {
namespace {

constexpr std::array<uint8_t, 32> kAltBn128FieldModulusQ = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47
};

bool IsCanonicalFqElement(const uint8_t* be32) {
    for (size_t i = 0; i < kAltBn128FieldModulusQ.size(); ++i) {
        if (be32[i] < kAltBn128FieldModulusQ[i]) {
            return true;
        }
        if (be32[i] > kAltBn128FieldModulusQ[i]) {
            return false;
        }
    }
    return false;
}

bool ValidatePairingInputFieldBounds(const uint8_t* input, size_t input_size) {
    constexpr size_t kPairStride = 192;
    constexpr size_t kFieldCountPerPair = 6;  // G1(x,y) + G2(x.c1,x.c0,y.c1,y.c0)
    constexpr size_t kFieldBytes = 32;
    const size_t pair_count = input_size / kPairStride;
    for (size_t p = 0; p < pair_count; ++p) {
        const size_t base = p * kPairStride;
        for (size_t f = 0; f < kFieldCountPerPair; ++f) {
            if (!IsCanonicalFqElement(input + base + f * kFieldBytes)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace

ContractaltBn128PairingProduct::ContractaltBn128PairingProduct(const std::string& create_address)
        : ContractInterface(create_address) {}

ContractaltBn128PairingProduct::~ContractaltBn128PairingProduct() {}

int ContractaltBn128PairingProduct::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        return kContractError;
    }

    const int64_t gas_used = (45000 + param.data.size() * 34000);
    if (res->gas_left < gas_used) {
        return kContractError;
    }

    // EIP-197: concatenation of (G1,G2) pairs; each pair is 192 bytes.
    constexpr size_t kEip197PairStrideBytes = 192;
    if (param.data.size() % kEip197PairStrideBytes != 0) {
        return kContractError;
    }
    const auto* input = reinterpret_cast<const uint8_t*>(param.data.data());
    if (!ValidatePairingInputFieldBounds(input, param.data.size())) {
        return kContractError;
    }

    bytesConstRef bytes_ref((byte*)param.data.c_str(), param.data.size());
    std::pair<bool, bytes> add_res = alt_bn128_pairing_product(bytes_ref);
    if (!add_res.first) {
        return kContractError;
    }

    res->output_data = new uint8_t[add_res.second.size()];
    memcpy((void*)res->output_data, &add_res.second.at(0), add_res.second.size());
    res->output_size = add_res.second.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_used;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace seth
