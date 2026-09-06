#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>

namespace shardora {

namespace shardoravm {

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
//   Must match the assembly sstore slot in CrossShardBase.sol.
//   The Solidity literal 0xc1f51986...01234567 has 63 hex digits (odd), so the
//   compiler left-pads it to 64 digits: 0x0c1f51986c7b4d6e0c3e3a3f5a6b7d8e9f0a1b2c3d4e5f6789abcdef01234567.
//   This C++ constant must equal that padded value.
// ─────────────────────────────────────────────────────────────────────────────
inline const evmc::bytes32 kIsCrossShardBaseSlot = {{
    0x0c, 0x1f, 0x51, 0x98, 0x6c, 0x7b, 0x4d, 0x6e,
    0x0c, 0x3e, 0x3a, 0x3f, 0x5a, 0x6b, 0x7d, 0x8e,
    0x9f, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
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
    uint64_t             amount          = 0;  // low 64 bits (backward compat)
    std::string          amount_bytes;         // full 32-byte BE uint256; non-empty overrides amount
    uint64_t             nonce           = 0;
    int64_t              gas_cost        = 0;
    uint32_t             dest_shard_id   = 0;  // target shard (from toShard param)
    uint32_t             dest_pool_index = 0;  // target pool  (from toPool param)

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

} // namespace shardoravm

} // namespace shardora
