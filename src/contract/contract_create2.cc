#include "contract/contract_create2.h"
#include "common/hash.h"
#include "common/encode.h"

namespace seth {

namespace contract {

ContractCreate2::ContractCreate2(const std::string& create_address)
    : ContractInterface(create_address) {}

ContractCreate2::~ContractCreate2() {}

int ContractCreate2::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    
    // 1. Gas 检查
    if (param.gas < gas_cast_) {
        return kContractError;
    }

    // 2. 参数解析
    // 按照约定，data 前 32 字节为 salt，后面为 init_code
    if (param.data.size() < 32) {
        SETH_DEBUG("CREATE2 failed: data size too small");
        return kContractError;
    }

    std::string salt = param.data.substr(0, 32);
    std::string init_code = param.data.substr(32);

    // 3. 计算地址逻辑 (EIP-1014)
    // address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
    
    // 计算代码哈希
    std::string code_hash = common::Hash::keccak256(init_code);

    // 拼接缓冲区
    std::string buffer;
    buffer.reserve(1 + 20 + 32 + 32); 
    buffer.push_back(static_cast<char>(0xff));     // 0xff 前缀
    buffer.append(param.from);                      // 20字节部署者地址
    buffer.append(salt);                           // 32字节盐
    buffer.append(code_hash);                      // 32字节代码哈希

    // 执行最终哈希并截断前 12 字节
    std::string final_hash = common::Hash::keccak256(buffer);
    std::string predicted_address = final_hash.substr(12);

    // 4. 设置返回结果
    res->output_size = predicted_address.size();
    res->output_data = new uint8_t[res->output_size];
    memcpy((void*)res->output_data, predicted_address.data(), res->output_size);

    // 设置创建地址标识（CREATE2 实际上是在创建新地址，这里按 Ecrecover 风格填充）
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));

    res->gas_left -= gas_cast_;

    SETH_DEBUG("CREATE2 predicted address: %s, sender: %s, salt: %s", 
        common::Encode::HexEncode(predicted_address).c_str(),
        common::Encode::HexEncode(param.from).c_str(),
        common::Encode::HexEncode(salt).c_str());

    return kContractSuccess;
}

}  // namespace contract

}  // namespace seth