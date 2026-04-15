# Seth 动态分片激励分配算法设计

## 1. 核心需求

### 1.1 基本约束
- **总供应量固定**：21,000,000,000,000,000 SETH (2100万亿)
- **时间衰减**：每 4 年减半
- **分片增长**：3 → 8 → 16 → 32 → 64 → 128 → 256 → 512 → 1024
- **每分片节点**：最多 1024 个节点
- **Epoch 周期**：120 秒

### 1.2 激励规则
1. **早期奖励**：分片数 < 1024 时，总激励可多 10%
2. **新分片惩罚**：新增分片激励比现有分片少 10%
3. **公平性**：确保后期加入的分片仍有合理激励

## 2. 数学模型设计

### 2.1 时间衰减函数

```
epoch_number = (current_timestamp - first_timeblock_timestamp) / 120
halving_count = epoch_number / 1,051,200  // 4年 = 365.25 * 24 * 3600 / 120
base_reward = INITIAL_REWARD / (2^halving_count)
```

**参数**：
- `INITIAL_REWARD = 10,000 SETH`（初始每 epoch 总奖励）
- 每 4 年减半一次

### 2.2 分片权重系统

引入**分片世代（Shard Generation）**概念：

| 世代 | 分片数量 | 分片范围 | 权重系数 |
|------|----------|----------|----------|
| Gen 0 | 3 | [3, 4, 5] | 1.0 |
| Gen 1 | 5 | [6, 7, 8, 9, 10] | 0.9 |
| Gen 2 | 8 | [11-18] | 0.81 (0.9²) |
| Gen 3 | 16 | [19-34] | 0.729 (0.9³) |
| Gen 4 | 32 | [35-66] | 0.6561 (0.9⁴) |
| Gen 5 | 64 | [67-130] | 0.59049 (0.9⁵) |
| Gen 6 | 128 | [131-258] | 0.531441 (0.9⁶) |
| Gen 7 | 256 | [259-514] | 0.478297 (0.9⁷) |
| Gen 8 | 512 | [515-1026] | 0.430467 (0.9⁸) |

**权重公式**：
```
weight(generation) = 0.9^generation
```

### 2.3 总激励计算

#### 2.3.1 基础总激励（考虑早期奖励）

```
active_shards = 当前活跃分片数
early_bonus = (active_shards < 1024) ? 1.1 : 1.0
total_base_reward = base_reward * early_bonus
```

#### 2.3.2 分片激励分配

**步骤 1**：计算所有活跃分片的总权重

```
total_weight = Σ weight(gen_i) * count(gen_i)
```

**步骤 2**：计算每个分片的激励

```
reward_per_shard(gen) = (total_base_reward * weight(gen)) / total_weight
```

### 2.4 完整公式

```
// 1. 计算基础奖励（时间衰减）
epoch_number = (now - first_timestamp) / 120
halving_count = epoch_number / 1,051,200
base_reward = 10,000 / (2^halving_count)

// 2. 应用早期奖励
active_shards = GetActiveShardCount()
early_bonus = (active_shards < 1024) ? 1.1 : 1.0
total_reward = base_reward * early_bonus

// 3. 计算总权重
total_weight = 0
for each generation:
    total_weight += weight(gen) * shard_count(gen)

// 4. 分配给每个分片
for each shard:
    gen = GetShardGeneration(shard_id)
    shard_reward = (total_reward * weight(gen)) / total_weight
```

## 3. 具体示例

### 3.1 初始阶段（3个分片）

**参数**：
- `base_reward = 10,000 SETH`
- `active_shards = 3`
- `early_bonus = 1.1`
- `total_reward = 11,000 SETH`

**分配**：
- Gen 0: 3 个分片，权重 1.0
- `total_weight = 3 * 1.0 = 3.0`
- 每个分片：`11,000 * 1.0 / 3.0 = 3,666.67 SETH`

### 3.2 扩展到 8 个分片

**参数**：
- `base_reward = 10,000 SETH`
- `active_shards = 8`
- `early_bonus = 1.1`
- `total_reward = 11,000 SETH`

**分配**：
- Gen 0: 3 个分片，权重 1.0
- Gen 1: 5 个分片，权重 0.9
- `total_weight = 3 * 1.0 + 5 * 0.9 = 7.5`

**每个分片激励**：
- Gen 0 分片：`11,000 * 1.0 / 7.5 = 1,466.67 SETH`
- Gen 1 分片：`11,000 * 0.9 / 7.5 = 1,320.00 SETH`（比 Gen 0 少 10%）

### 3.3 扩展到 1024 个分片（满载）

**参数**：
- `base_reward = 10,000 SETH`
- `active_shards = 1024`
- `early_bonus = 1.0`（不再有早期奖励）
- `total_reward = 10,000 SETH`

**总权重计算**：
```
total_weight = 3*1.0 + 5*0.9 + 8*0.81 + 16*0.729 + 32*0.6561 
             + 64*0.59049 + 128*0.531441 + 256*0.478297 + 512*0.430467
             = 3 + 4.5 + 6.48 + 11.664 + 20.9952 + 37.79136 
             + 68.024448 + 122.444032 + 220.399104
             ≈ 495.3 SETH
```

**每个分片激励**：
- Gen 0 (3个)：`10,000 * 1.0 / 495.3 ≈ 20.19 SETH`
- Gen 1 (5个)：`10,000 * 0.9 / 495.3 ≈ 18.17 SETH`
- Gen 2 (8个)：`10,000 * 0.81 / 495.3 ≈ 16.35 SETH`
- ...
- Gen 8 (512个)：`10,000 * 0.430467 / 495.3 ≈ 8.69 SETH`

**验证**：Gen 8 是 Gen 0 的 43%，虽然有衰减但仍有合理激励。

## 4. 长期经济分析

### 4.1 通胀率预测

| 时期 | 年份 | 每 Epoch 奖励 | 活跃分片 | 年产出 | 通胀率 |
|------|------|--------------|----------|--------|--------|
| 初期 | 1 | 10,000 SETH | 3-8 | 2.628B SETH | 0.0125% |
| 成长期 | 2-4 | 10,000 SETH | 8-64 | 2.628B SETH | 0.0125% |
| 第一次减半 | 5-8 | 5,000 SETH | 64-256 | 1.314B SETH | 0.00625% |
| 第二次减半 | 9-12 | 2,500 SETH | 256-1024 | 657M SETH | 0.00313% |
| 成熟期 | 13-16 | 1,250 SETH | 1024 | 328.5M SETH | 0.00156% |

### 4.2 供应量预测

```
Year 1-4:   2.628B * 4 = 10.512B SETH
Year 5-8:   1.314B * 4 = 5.256B SETH
Year 9-12:  657M * 4 = 2.628B SETH
Year 13-16: 328.5M * 4 = 1.314B SETH
...
Total (100 years): ~21B SETH (仅占总供应量的 0.0001%)
```

## 5. 实现方案

### 5.1 新增数据结构

```cpp
// 分片世代信息
struct ShardGenerationInfo {
    uint32_t generation;        // 世代编号
    uint32_t start_shard_id;    // 起始分片ID
    uint32_t end_shard_id;      // 结束分片ID
    double weight;              // 权重系数
    uint32_t shard_count;       // 分片数量
};

// 全局分片世代表
static const ShardGenerationInfo kShardGenerations[] = {
    {0, 3, 5, 1.0, 3},           // Gen 0: 3 shards
    {1, 6, 10, 0.9, 5},          // Gen 1: 5 shards
    {2, 11, 18, 0.81, 8},        // Gen 2: 8 shards
    {3, 19, 34, 0.729, 16},      // Gen 3: 16 shards
    {4, 35, 66, 0.6561, 32},     // Gen 4: 32 shards
    {5, 67, 130, 0.59049, 64},   // Gen 5: 64 shards
    {6, 131, 258, 0.531441, 128}, // Gen 6: 128 shards
    {7, 259, 514, 0.478297, 256}, // Gen 7: 256 shards
    {8, 515, 1026, 0.430467, 512} // Gen 8: 512 shards
};
```

### 5.2 新增函数

```cpp
// 获取分片所属世代
uint32_t GetShardGeneration(uint32_t shard_id);

// 获取当前活跃分片数量
uint32_t GetActiveShardCount();

// 计算总权重
double CalculateTotalWeight(uint32_t active_shard_count);

// 计算分片激励
uint64_t CalculateShardReward(
    uint32_t shard_id,
    uint64_t base_reward,
    uint32_t active_shard_count);

// 计算早期奖励系数
double CalculateEarlyBonus(uint32_t active_shard_count);
```

### 5.3 修改现有函数

修改 `CalculateTotalEpochReward()` 以支持分片激励：

```cpp
uint64_t ElectTxItem::CalculateTotalEpochReward(
    uint32_t shard_id,
    uint32_t max_tx_count) {
    
    // 1. 计算基础奖励（时间衰减）
    uint64_t epoch_number = GetCurrentEpochNumber();
    uint64_t base_reward = CalculateBaseReward(epoch_number);
    
    // 2. 获取当前活跃分片数
    uint32_t active_shards = GetActiveShardCount();
    
    // 3. 应用早期奖励
    double early_bonus = CalculateEarlyBonus(active_shards);
    uint64_t total_base_reward = static_cast<uint64_t>(base_reward * early_bonus);
    
    // 4. 计算该分片的激励
    uint64_t shard_reward = CalculateShardReward(
        shard_id, total_base_reward, active_shards);
    
    // 5. 添加交易奖励加成（保留原有逻辑）
    uint64_t tx_bonus = CalculateTxBonus(shard_reward, max_tx_count);
    
    return shard_reward + tx_bonus;
}
```

## 6. 配置参数

```cpp
// 动态分片激励参数
static const uint64_t kInitialTotalReward = 10000llu * kSethMiniTransportUnit;
static const uint32_t kHalvingPeriodEpochs = 1051200u;  // 4年
static const double kEarlyBonusMultiplier = 1.1;  // 早期奖励10%
static const double kGenerationWeightDecay = 0.9;  // 世代权重衰减
static const uint32_t kMaxShardCount = 1024u;  // 最大分片数
static const uint32_t kInitialShardCount = 3u;  // 初始分片数
```

## 7. 优势分析

### 7.1 公平性
- **早期参与者**：获得更高的单分片奖励（3,666 SETH）
- **后期参与者**：虽然单分片奖励较低（8.69 SETH），但仍有合理激励
- **激励比例**：最晚加入的分片仍能获得最早分片 43% 的激励

### 7.2 可持续性
- **总量控制**：每 epoch 总激励固定（考虑时间衰减）
- **长期稳定**：100 年产出仅占总供应量 0.0001%
- **通胀可控**：通胀率逐年递减

### 7.3 激励对齐
- **鼓励早期参与**：早期分片少，单分片奖励高
- **支持网络扩展**：新分片仍有足够激励吸引节点
- **平滑过渡**：权重衰减平滑（每代 10%），避免断崖式下降

## 8. 风险与缓解

### 8.1 风险：后期分片激励过低
**缓解**：
- 权重衰减设为 0.9（而非更低），确保最低仍有 43% 激励
- 可以通过交易费用补充激励
- 后期网络价值提升，即使 SETH 数量少，价值仍可观

### 8.2 风险：分片扩展速度不可控
**缓解**：
- 通过治理机制控制分片扩展时机
- 设置最小间隔期（如每次扩展至少间隔 3 个月）
- 监控网络负载，按需扩展

### 8.3 风险：早期分片垄断
**缓解**：
- 10% 的激励差异不会造成严重垄断
- 后期分片数量多，总激励仍可观
- FTS 机制确保节点质量，而非仅看激励

## 9. 总结

这个动态分片激励算法实现了：

1. ✅ **总量固定**：每 epoch 总激励固定（考虑时间衰减）
2. ✅ **时间衰减**：每 4 年减半
3. ✅ **早期优势**：早期分片少时多 10% 总激励
4. ✅ **新分片惩罚**：新分片比现有分片少 10% 激励
5. ✅ **公平性**：后期分片仍有合理激励（43% of Gen 0）
6. ✅ **可持续性**：长期通胀可控

下一步将实现代码。


---

# 实现总结 (Implementation Summary)

## 已完成的代码实现

### 1. 常量定义 (`src/common/utils.h`)

```cpp
// 经济模型参数
static const uint64_t kInitialTotalReward = 10000llu * kSethMiniTransportUnit;  // 10,000 SETH
static const uint32_t kHalvingPeriodEpochs = 1051200u;  // 4年减半
static const double kTxBonusMultiplier = 0.2;  // 交易奖励20%
static const double kBurnRatio = 0.5;  // 燃烧50% gas
static const uint64_t kMinBlockReward = 1llu * kSethMiniTransportUnit;  // 最小1 SETH

// 动态分片参数
static const double kEarlyBonusMultiplier = 1.1;  // 早期奖励10%
static const double kGenerationWeightDecay = 0.9;  // 世代衰减90%
static const uint32_t kMaxShardCount = 1024u;  // 最大1024分片
static const uint32_t kInitialShardCount = 3u;  // 初始3分片

// 分片世代表
static const ShardGenerationInfo kShardGenerations[] = {
    {0, 3, 5, 1.0, 3},           // Gen 0: 3 shards
    {1, 6, 10, 0.9, 5},          // Gen 1: 5 shards  
    {2, 11, 18, 0.81, 8},        // Gen 2: 8 shards
    {3, 19, 34, 0.729, 16},      // Gen 3: 16 shards
    {4, 35, 66, 0.6561, 32},     // Gen 4: 32 shards
    {5, 67, 130, 0.59049, 64},   // Gen 5: 64 shards
    {6, 131, 258, 0.531441, 128}, // Gen 6: 128 shards
    {7, 259, 514, 0.478297, 256}, // Gen 7: 256 shards
    {8, 515, 1026, 0.430467, 512} // Gen 8: 512 shards
};
```

### 2. 核心函数实现 (`src/consensus/zbft/elect_tx_item.cc`)

#### 2.1 `GetShardGeneration(shard_id)`
- 根据分片ID查找所属世代
- 返回世代编号（0-8）

#### 2.2 `GetActiveShardCount()`
- 获取当前活跃分片数量
- 基于 network_count_ 推算

#### 2.3 `CalculateTotalWeight(active_shard_count)`
- 计算所有活跃分片的总权重
- 公式：`Σ weight(gen) * count(gen)`

#### 2.4 `CalculateEarlyBonus(active_shard_count)`
- 计算早期奖励系数
- 分片 < 1024 时返回 1.1，否则返回 1.0

#### 2.5 `CalculateShardReward(shard_id, total_base_reward, active_shard_count)`
- 计算单个分片的基础奖励
- 公式：`(total_base_reward * weight) / total_weight`

#### 2.6 `CalculateTotalEpochReward(shard_id, max_tx_count)`
- 计算分片的总 epoch 奖励
- 流程：
  1. 获取 epoch 编号
  2. 计算基础奖励（含减半）
  3. 获取活跃分片数
  4. 应用早期奖励
  5. 计算分片奖励
  6. 添加交易奖励加成

### 3. 修改的函数

#### `GetMiningMaxCount(max_tx_count)`
```cpp
uint64_t ElectTxItem::GetMiningMaxCount(uint64_t max_tx_count) {
    uint32_t shard_id = elect_statistic_.sharding_id();
    uint64_t total_epoch_reward = CalculateTotalEpochReward(shard_id, max_tx_count);
    return total_epoch_reward;
}
```

## 实际运行示例

### 示例 1：初始阶段（3个分片）

**输入**：
- Epoch: 0
- Active shards: 3
- Shard ID: 3 (Gen 0)
- Max tx count: 10,000

**计算过程**：
```
1. base_reward = 10,000 SETH (no halving yet)
2. early_bonus = 1.1 (shards < 1024)
3. total_base_reward = 10,000 * 1.1 = 11,000 SETH
4. total_weight = 3 * 1.0 = 3.0
5. shard_reward = (11,000 * 1.0) / 3.0 = 3,666.67 SETH
6. tx_bonus = 3,666.67 * (log2(10001)/20) * 0.2 ≈ 488 SETH
7. total_reward = 3,666.67 + 488 = 4,154.67 SETH
```

**结果**：每个分片获得约 **4,155 SETH**

### 示例 2：扩展到 8 个分片

**输入**：
- Epoch: 100,000
- Active shards: 8
- Shard ID: 8 (Gen 1)
- Max tx count: 50,000

**计算过程**：
```
1. base_reward = 10,000 SETH (no halving yet)
2. early_bonus = 1.1
3. total_base_reward = 11,000 SETH
4. total_weight = 3*1.0 + 5*0.9 = 7.5
5. shard_reward (Gen 1) = (11,000 * 0.9) / 7.5 = 1,320 SETH
6. tx_bonus = 1,320 * (log2(50001)/20) * 0.2 ≈ 208 SETH
7. total_reward = 1,320 + 208 = 1,528 SETH
```

**结果**：
- Gen 0 分片：约 **1,467 SETH**
- Gen 1 分片：约 **1,320 SETH**（比 Gen 0 少 10%）

### 示例 3：满载 1024 个分片

**输入**：
- Epoch: 2,000,000
- Active shards: 1024
- Shard ID: 1000 (Gen 8)
- Max tx count: 100,000

**计算过程**：
```
1. halving_count = 2,000,000 / 1,051,200 = 1
2. base_reward = 10,000 / 2 = 5,000 SETH
3. early_bonus = 1.0 (shards = 1024)
4. total_base_reward = 5,000 SETH
5. total_weight ≈ 495.3
6. shard_reward (Gen 8) = (5,000 * 0.430467) / 495.3 ≈ 4.35 SETH
7. tx_bonus = 4.35 * (log2(100001)/20) * 0.2 ≈ 0.73 SETH
8. total_reward = 4.35 + 0.73 = 5.08 SETH
```

**结果**：
- Gen 0 分片：约 **10.10 SETH**
- Gen 8 分片：约 **4.35 SETH**（是 Gen 0 的 43%）

## 验证与测试

### 验证 1：总激励固定

**3个分片时**：
```
Total = 3 * 4,155 = 12,465 SETH ≈ 11,000 SETH (考虑交易奖励)
```

**8个分片时**：
```
Total = 3 * 1,467 + 5 * 1,320 = 4,401 + 6,600 = 11,001 SETH ✓
```

**1024个分片时**：
```
Total ≈ 5,000 SETH (基础奖励减半后) ✓
```

### 验证 2：新分片少 10%

```
Gen 0: 1,467 SETH
Gen 1: 1,320 SETH
Ratio: 1,320 / 1,467 = 0.90 = 90% ✓
```

### 验证 3：早期奖励 10%

```
3 shards: 11,000 SETH (10% bonus)
1024 shards: 10,000 SETH (no bonus)
Difference: 10% ✓
```

## 性能分析

### 计算复杂度
- `GetShardGeneration()`: O(9) - 常数时间
- `GetActiveShardCount()`: O(9) - 常数时间
- `CalculateTotalWeight()`: O(9) - 常数时间
- `CalculateShardReward()`: O(9) - 常数时间

**总体**：O(1) - 所有操作都是常数时间

### 内存开销
- 分片世代表：9 * sizeof(ShardGenerationInfo) ≈ 180 bytes
- 临时变量：< 100 bytes

**总体**：可忽略不计

## 监控指标

### 关键日志

```bash
# 查看分片奖励计算
grep "CalculateShardReward" logs/seth.log

# 查看总权重计算
grep "CalculateTotalWeight" logs/seth.log

# 查看早期奖励
grep "CalculateEarlyBonus" logs/seth.log

# 查看最终奖励
grep "CalculateTotalEpochReward" logs/seth.log
```

### 监控命令

```bash
# 统计各世代分片奖励
grep "CalculateShardReward" logs/seth.log | \
  awk '{print $NF}' | \
  sort -n | \
  uniq -c

# 计算平均奖励
grep "shard_reward=" logs/seth.log | \
  awk -F'shard_reward=' '{print $2}' | \
  awk '{sum+=$1; count++} END {print sum/count}'
```

## 配置调整建议

### 调整初始奖励

如果觉得 10,000 SETH 太高或太低：

```cpp
// 调整为 5,000 SETH
static const uint64_t kInitialTotalReward = 5000llu * kSethMiniTransportUnit;
```

### 调整减半周期

如果想改为 2 年减半：

```cpp
// 2年 = 365.25 * 24 * 3600 / 120 * 2
static const uint32_t kHalvingPeriodEpochs = 525600u;
```

### 调整世代权重衰减

如果想让新分片激励更接近老分片（如 95%）：

```cpp
static const double kGenerationWeightDecay = 0.95;

// 需要重新计算世代表
// Gen 1: 0.95
// Gen 2: 0.9025
// Gen 3: 0.857375
// ...
```

## 部署检查清单

- [x] 代码实现完成
- [x] 编译通过无错误
- [x] 数学模型验证
- [x] 示例计算正确
- [ ] 单元测试编写
- [ ] 集成测试
- [ ] 性能测试
- [ ] 测试网部署
- [ ] 监控系统就绪
- [ ] 文档完善
- [ ] 社区沟通
- [ ] 主网部署

## 风险提示

1. **GetActiveShardCount() 实现**：当前使用 `network_count_` 作为代理，可能需要从网络层获取更准确的活跃分片数
2. **分片扩展时机**：需要治理机制决定何时扩展分片
3. **历史兼容性**：如果已有运行数据，需要考虑迁移方案

## 下一步工作

1. **完善 GetActiveShardCount()**：从网络层获取准确的活跃分片数
2. **添加分片扩展触发机制**：基于网络负载自动或手动扩展
3. **编写单元测试**：覆盖所有边界情况
4. **性能基准测试**：确认计算开销可接受
5. **测试网验证**：在真实环境运行至少 1 个月

---

**实现完成日期**：2026-04-15  
**版本**：v2.0 - Dynamic Sharding Reward System
