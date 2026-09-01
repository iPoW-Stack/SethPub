#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>

namespace seth {

namespace sethvm {

// ─────────────────────────────────────────────────────────────────────────────
// kCrossShardSystemExecutor
//   Fixed consensus-controlled address used as msg.sender when calling
//   systemExecuteCrossTransfer / systemExecuteCrossStorage on derived shards.
//   Value = ASCII("SYSTEM_EXECUTOR_V1") + 0x0000, 20 bytes.
//   Solidity counterpart:
//     address internal constant SYSTEM_EXECUTOR_ADDRESS =
//         0x53595354454d5f4558454355544f525f56310000;
// ─────────────────────────────────────────────────────────────────────────────
inline const evmc::address kCrossShardSystemExecutor = {{
    0x53, 0x59, 0x53, 0x54, 0x45, 0x4d, 0x5f, 0x45,
    0x58, 0x45, 0x43, 0x55, 0x54, 0x4f, 0x52, 0x5f,
    0x56, 0x31, 0x00, 0x00
}};

// ─────────────────────────────────────────────────────────────────────────────
// IS_CROSS_SHARD_BASE_SLOT
//   keccak256("seth.cross_shard_base.marker.v1")
//   Must match the assembly sstore slot in CrossShardBase.sol:
//     bytes32 private constant IS_CROSS_SHARD_BASE_SLOT =
//         0xc1f51986c7b4d6e0c3e3a3f5a6b7d8e9f0a1b2c3d4e5f6789abcdef01234567;
// ─────────────────────────────────────────────────────────────────────────────
inline const evmc::bytes32 kIsCrossShardBaseSlot = {{
    0xc1, 0xf5, 0x19, 0x86, 0xc7, 0xb4, 0xd6, 0xe0,
    0xc3, 0xe3, 0xa3, 0xf5, 0xa6, 0xb7, 0xd8, 0xe9,
    0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x67
}};

// CrossShardBase 合约部署 gas 倍数
inline constexpr uint64_t kCrossShardBaseGasMultiplier = 16;

// 每笔跨链消息的路由 gas 成本（EVM 执行完毕后叠加进 gas_used）
inline constexpr int64_t kCrossTransferGasCost  = 21000;
inline constexpr int64_t kCrossSetStorageGasCost = 5000;

// ─────────────────────────────────────────────────────────────────────────────
// CrossShardPendingAction
//   emit_log() 拦截 CrossTransferOut / CrossStorageOut 事件后写入此结构，
//   待 EVM 执行完毕后由 contract_call.cc 转换为 cross_to_map_ 条目。
// ─────────────────────────────────────────────────────────────────────────────
enum class CrossShardActionType : uint8_t {
    kTransfer    = 0,
    kSetStorage  = 1,
};

struct CrossShardPendingAction {
    CrossShardActionType type             = CrossShardActionType::kTransfer;
    std::string          emitter;         // 发起合约地址（20 字节 raw string）
    std::string          base_root_address; // CrossTransferOut topics[1]（20 字节 raw string）
    std::string          to;             // 目标地址（20 字节 raw string）
    uint64_t             amount          = 0;
    uint64_t             nonce           = 0;
    int64_t              gas_cost        = 0;

    // 仅 kSetStorage 使用
    std::string          storage_key;    // 32 字节 raw
    std::string          storage_val;    // 任意长度
};

// ─────────────────────────────────────────────────────────────────────────────
// JournalFrameSnapshot
//   每次 EVM call 入栈时保存当前 pending_cross_actions_ 的游标和已扣 gas，
//   子调用 revert 时回滚到此快照。
// ─────────────────────────────────────────────────────────────────────────────
struct JournalFrameSnapshot {
    size_t  actions_size  = 0;  // pending_cross_actions_.size() 的快照
    int64_t gas_charged   = 0;  // cross_gas_charged_ 的快照
};

} // namespace sethvm

} // namespace seth
