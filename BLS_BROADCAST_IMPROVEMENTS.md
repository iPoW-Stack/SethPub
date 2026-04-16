# BLS 广播机制完善总结

## 概述
完善了 BLS DKG 广播机制，确保每个阶段（验证、密钥交换、完成）不同节点的消息分散性传播，避免网络拥塞。

## 主要改进

### 1. 动态验证加速机制（bls_manager.cc）

**文件:** `d:\work\SethPub\src\bls\bls_manager.cc`

**修改内容:**
- 添加 `kBatchVerifyFastIntervalMs` 常量（3秒）用于加速验证
- 在 `BatchVerifyFinishItems()` 中实现动态验证间隔
- 当 `now_us > begin_time_us() + dkg_period_us() * 9` 时，验证频率从 30 秒加快到 3 秒

**代码示例:**
```cpp
static const uint64_t kBatchVerifyIntervalMs = 30000u;  // 30 seconds
static const uint64_t kBatchVerifyFastIntervalMs = 3000u;  // 3 seconds

void BlsManager::BatchVerifyFinishItems() {
    uint64_t now_ms = common::TimeUtils::TimestampMs();
    uint64_t now_us = common::TimeUtils::TimestampUs();
    
    for (auto& [network_id, finish_item] : finish_networks_map_) {
        // 根据 DKG 时间动态调整验证间隔
        uint64_t verify_interval_ms = kBatchVerifyIntervalMs;
        auto tmp_bls = waiting_bls_.load();
        if (tmp_bls != nullptr && tmp_bls->elect_hegiht() > 0) {
            if (now_us > (tmp_bls->begin_time_us() + tmp_bls->dkg_period_us() * 9)) {
                verify_interval_ms = kBatchVerifyFastIntervalMs;  // 加速到 3 秒
            }
        }
        // ...
    }
}
```

### 2. 公开访问器方法（bls_dkg.h）

**文件:** `d:\work\SethPub\src\bls\bls_dkg.h`

**新增方法:**
- `begin_time_us()` - 获取 DKG 开始时间（微秒）
- `dkg_period_us()` - 获取 DKG 周期时长（微秒）

```cpp
uint64_t begin_time_us() const {
    return begin_time_us_;
}

int64_t dkg_period_us() const {
    return kDkgPeriodUs;
}
```

### 3. 分散性广播机制（bls_dkg.cc 和 bls_dkg.h）

**文件:** 
- `d:\work\SethPub\src\bls\bls_dkg.h`
- `d:\work\SethPub\src\bls\bls_dkg.cc`

**新增私有方法:**

#### a. `ConfigureScatterBroadcastParam()`
为不同的 BLS 阶段配置分散性广播参数：

```cpp
void ConfigureScatterBroadcastParam(
    transport::protobuf::BroadcastParam* broadcast,
    uint32_t phase,
    uint64_t elapsed_us);
```

**功能:**
- **邻居数量调整**（阶段化）：
  - 阶段 0（验证）：13 + 4 = 17 个邻居（快速验证传播）
  - 阶段 1（密钥交换）：13 个邻居（标准）
  - 阶段 2（完成）：13 - 4 = 9 个邻居（集中广播到根议会）

- **跳数限制调整**（阶段化）：
  - 阶段 0（验证）：16 跳（全网）
  - 阶段 1（密钥交换）：14 跳（中等）
  - 阶段 2（完成）：20 跳（目标到根议会）

- **重叠率调整**（阶段化）：
  - 阶段 0（验证）：0.9（高重叠率以加快传播）
  - 阶段 1（密钥交换）：0.7（中等重叠）
  - 阶段 2（完成）：0.5（低重叠率用于精准投递）

- **节点错开机制**：基于节点索引计算偏移，确保不同节点在不同时间广播

#### b. `GetPhaseBasedNeighborCount()`
根据 BLS 阶段和集群规模计算邻居数量：

```cpp
uint32_t GetPhaseBasedNeighborCount(uint32_t phase, uint32_t member_count);
```

**逻辑:**
- 基础邻居数：13
- 最小邻居数：member_count / 4
- 最大邻居数：member_count
- 按阶段调整：
  - 验证阶段 +4
  - 交换阶段 +0
  - 完成阶段 -4

#### c. `GetPhaseBasedDelayUs()`
返回各阶段的节点错开延迟：

```cpp
uint64_t GetPhaseBasedDelayUs(uint32_t phase);
```

**延迟设置:**
- 验证阶段（Phase 0）：50ms（快速错开）
- 交换阶段（Phase 1）：100ms（中等错开）
- 完成阶段（Phase 2）：150ms（长延迟避免网络拥塞）

#### d. `CreateDkgMessage()` 增强
修改消息创建逻辑以应用分散性广播参数：

```cpp
void CreateDkgMessage(transport::MessagePtr msg_ptr) {
    // ... 现有代码 ...
    
    // 确定 BLS 阶段
    uint32_t phase = 0;  // 0: verify, 1: swap, 2: finish
    if (bls_msg.has_swap_req()) {
        phase = 1;
    } else if (bls_msg.has_finish_req()) {
        phase = 2;
    }
    
    // 应用分散性广播配置
    uint64_t now_us = common::TimeUtils::TimestampUs();
    uint64_t elapsed_us = (begin_time_us_ > 0) ? (now_us - begin_time_us_) : 0;
    ConfigureScatterBroadcastParam(broad_param, phase, elapsed_us);
    
    // ... 继续签名等处理 ...
}
```

## 工作流程

### 3 阶段广播策略

```
┌─────────────────────────────────────────────────────────────┐
│           BLS DKG 3 阶段广播分散性机制                        │
└─────────────────────────────────────────────────────────────┘

阶段 0: 验证广播（Verify Phase）
├─ 邻居数: 17 个（最多）
├─ 跳数: 16 (全网)
├─ 重叠: 0.9 (高)
├─ 错开延迟: 50ms
└─ 目标: 快速验证消息传播

阶段 1: 密钥交换广播（Swap Phase）
├─ 邻居数: 13 个（标准）
├─ 跳数: 14 (中等)
├─ 重叠: 0.7 (中等)
├─ 错开延迟: 100ms
└─ 目标: 均衡的密钥交换传播

阶段 2: 完成广播（Finish Phase）
├─ 邻居数: 9 个（最少）
├─ 跳数: 20 (到根议会)
├─ 重叠: 0.5 (低)
├─ 错开延迟: 150ms
└─ 目标: 精准投递到根议会
```

### 节点广播分散示例

假设集群有 16 个节点，阶段 0（验证）延迟 50ms：

```
节点 0:  t = 0ms       广播
节点 1:  t = 3ms       广播 (50ms / 16)
节点 2:  t = 6ms       广播
节点 3:  t = 9ms       广播
...
节点 15: t = 46ms      广播
```

这样避免了网络拥塞，提高了消息传递效率。

## 技术细节

### 广播参数对象
每个消息的广播参数包含：
- `neighbor_count`: 邻居节点数
- `hop_limit`: 最大跳数
- `hop_to_layer`: 层次跳转
- `overlap`: 消息重叠率
- `bloomfilter`: 布隆过滤器配置

### 时间计算
- 使用微秒精度时间戳确保精确的错开
- DKG 周期从 `begin_time_us_` 开始计算
- 每个节点基于自身索引计算唯一的广播时间

## 编译依赖

新增 `#include <algorithm>` 以支持 `std::max` 和 `std::min` 函数。

## 性能优势

1. **减少网络拥塞**：节点错开广播，避免同时发送
2. **加快消息传播**：验证阶段高邻居数和重叠率
3. **精准投递**：完成阶段低邻居数专注于根议会
4. **自适应调整**：根据 DKG 阶段动态改变策略
5. **加速 DKG 完成**：当接近完成时（9 周期后）加快验证频率

## 日志输出

系统会输出调试日志显示广播配置：

```
[bls]BlsDkg scatter broadcast config: phase=0, neighbors=17, hop_limit=16, overlap=0.9, 
local_member_idx=3, node_offset_us=9375, member_count=16
```

## 后续优化空间

1. 可根据实际网络状况动态调整参数
2. 可基于节点地理位置进行更智能的邻居选择
3. 可实现递进式的邻居扩展策略
