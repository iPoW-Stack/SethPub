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
    
    // 1. 严格的 Gas 检查与动态扣费
    // 标准 Create2 基础 Gas 是 32000，且每 32 字节 init_code 额外消耗 6 Gas
    if (res->gas_left < gas_cast_) {
        SETH_ERROR("CREATE2 gas_left < dynamic_gas, %lu, %lu", res->gas_left, gas_cast_);
        return kContractError;
    }

    // 2. 参数解析
    // data 布局: [32字节 Salt][N字节 InitCode]
    if (param.data.size() < 32) {
        SETH_ERROR("CREATE2 param data size < 32, %lu", param.data.size());
        return kContractError;
    }

    std::string salt = param.data.substr(0, 32);      // 已经是 32 字节
    std::string init_code = param.data.substr(32);    // 剩下的所有数据

    // 3. 计算地址逻辑 (EIP-1014)
    // 核心公式: keccak256(0xff ++ address ++ salt ++ keccak256(init_code))[12:]
    
    // A. 计算 init_code 的哈希
    std::string code_hash = common::Hash::keccak256(init_code);

    // B. 准备 85 字节的 Buffer (1 + 20 + 32 + 32)
    std::string buffer;
    buffer.reserve(85); 
    buffer.push_back(static_cast<char>(0xff));         // 1 字节前缀
    
    // 重要：确保部署者地址是 20 字节二进制（如果 param.from 包含 padding，需处理）
    if (param.from.size() > 20) {
        buffer.append(param.from.substr(param.from.size() - 20)); 
    } else {
        buffer.append(param.from); 
    }

    buffer.append(salt);                               // 32 字节盐
    buffer.append(code_hash);                          // 32 字节代码哈希

    // C. 执行最终哈希
    std::string final_hash = common::Hash::keccak256(buffer);
    
    // D. 截断：Keccak 输出 32 字节，取最后 20 字节作为地址
    // 假设 hash 输出是 binary string，偏移 12 字节开始取
    std::string predicted_address = final_hash.substr(12, 20);

    // 4. 设置返回结果
    // 注意：evmc_result 的 output 应该按照协议规范填充
    res->output_size = 20; 
    uint8_t* out = new uint8_t[20];
    memcpy(out, predicted_address.c_str(), predicted_address.size());
    res->output_data = out;

    // 5. 更新状态
    res->status_code = EVMC_SUCCESS;
    // 减去实际消耗的 Gas
    res->gas_left -= dynamic_gas;
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));

    SETH_DEBUG("CREATE2 predicted address: %s, from: %s, salt: %s, final_hash: %s",
        common::Encode::HexEncode(predicted_address).c_str(),
        common::Encode::HexEncode(param.from).c_str(),
        common::Encode::HexEncode(salt).c_str(),
        common::Encode::HexEncode(final_hash).c_str());
    return kContractSuccess;
}

}  // namespace contract

}  // namespace seth