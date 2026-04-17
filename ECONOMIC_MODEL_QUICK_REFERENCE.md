# Seth Economic Model - Quick Reference Guide

## 快速参考 | Quick Reference

### 核心公式 | Core Formulas

#### 1. 总奖励计算 | Total Reward Calculation
```
Total Epoch Reward = Base Reward + Transaction Bonus + Staking Pool

其中 | Where:
- Base Reward = Initial Reward / (2^halving_count)
- Transaction Bonus = Base Reward × (log2(tx_count + 1) / 20) × 0.5
- Staking Pool = Base Reward × 0.3
```

#### 2. 减半机制 | Halving Mechanism
```
Halving Count = Epoch Number / 262,800
Epoch Number = (Current Timestamp - First Timeblock Timestamp) / 120
```

#### 3. 燃烧机制 | Burn Mechanism
```
Gas Burned = Total Gas × 0.5
Gas Distributed = Total Gas × 0.5
```

### 关键参数 | Key Parameters

| 参数 | Parameter | 值 | Value | 说明 | Description |
|------|-----------|-----|-------|------|-------------|
| 初始奖励 | Initial Reward | 1000 SETH | 1000 SETH | 每 epoch 基础奖励 | Base reward per epoch |
| 减半周期 | Halving Period | 262,800 epochs | 262,800 epochs | 约1年 | ~1 year |
| 交易奖励倍数 | Tx Bonus Multiplier | 0.5 | 0.5 | 最多50%基础奖励 | Up to 50% of base |
| 质押奖励比例 | Staking Ratio | 0.3 | 0.3 | 30%基础奖励 | 30% of base |
| 燃烧比例 | Burn Ratio | 0.5 | 0.5 | 50% gas 费用 | 50% of gas fees |
| 最小奖励 | Min Reward | 1 SETH | 1 SETH | 最低保障 | Minimum guarantee |
| Epoch 周期 | Epoch Period | 120秒 | 120 seconds | 时间块周期 | Timeblock period |

### 奖励时间表 | Reward Schedule

| 年份 | Year | Epoch 范围 | Epoch Range | 每 Epoch 奖励 | Reward/Epoch | 年产出 | Annual Output |
|------|------|------------|-------------|--------------|--------------|--------|---------------|
| 1 | 1 | 0 - 262,799 | 0 - 262,799 | 1000 SETH | 1000 SETH | 262.8M SETH | 262.8M SETH |
| 2 | 2 | 262,800 - 525,599 | 262,800 - 525,599 | 500 SETH | 500 SETH | 131.4M SETH | 131.4M SETH |
| 3 | 3 | 525,600 - 788,399 | 525,600 - 788,399 | 250 SETH | 250 SETH | 65.7M SETH | 65.7M SETH |
| 4 | 4 | 788,400 - 1,051,199 | 788,400 - 1,051,199 | 125 SETH | 125 SETH | 32.85M SETH | 32.85M SETH |
| 5 | 5 | 1,051,200 - 1,313,999 | 1,051,200 - 1,313,999 | 62.5 SETH | 62.5 SETH | 16.43M SETH | 16.43M SETH |

### 代码位置 | Code Locations

#### 常量定义 | Constants
```
文件 | File: src/common/utils.h
行号 | Lines: ~280-287

- kInitialBlockReward
- kHalvingPeriodEpochs
- kTxBonusMultiplier
- kStakingRewardRatio
- kBurnRatio
- kMinBlockReward
- kMaxHalvingCount
```

#### 函数实现 | Function Implementation
```
文件 | File: src/consensus/zbft/elect_tx_item.cc
行号 | Lines: ~610-750

核心函数 | Core Functions:
- GetCurrentEpochNumber()
- CalculateBaseReward()
- CalculateTxBonus()
- CalculateStakingRewardPool()
- CalculateTotalEpochReward()
- ApplyBurnMechanism()
- GetMiningMaxCount() [modified]
- MiningToken() [modified]
```

#### 头文件 | Header File
```
文件 | File: src/consensus/zbft/elect_tx_item.h
行号 | Lines: ~90-96

函数声明 | Function Declarations
```

### 使用示例 | Usage Examples

#### 计算当前 Epoch 奖励 | Calculate Current Epoch Reward
```cpp
// 获取当前 epoch 编号
uint64_t epoch_num = GetCurrentEpochNumber();

// 计算总奖励（假设 max_tx_count = 100000）
uint64_t total_reward = CalculateTotalEpochReward(100000);

// 输出示例 | Example Output:
// Epoch 0: ~1800 SETH (1000 base + 500 tx_bonus + 300 staking)
// Epoch 262800: ~900 SETH (500 base + 250 tx_bonus + 150 staking)
```

#### 应用燃烧机制 | Apply Burn Mechanism
```cpp
uint64_t total_gas = 10000 * common::kSethMiniTransportUnit;  // 10000 SETH
uint64_t gas_to_distribute = 0;
uint64_t gas_burned = 0;

ApplyBurnMechanism(total_gas, &gas_to_distribute, &gas_burned);

// 结果 | Result:
// gas_burned = 5000 SETH
// gas_to_distribute = 5000 SETH
```

### 监控命令 | Monitoring Commands

#### 查看日志 | View Logs
```bash
# 查看奖励计算日志
grep "CalculateTotalEpochReward" logs/seth.log

# 查看燃烧机制日志
grep "ApplyBurnMechanism" logs/seth.log

# 查看挖矿分配日志
grep "MiningToken" logs/seth.log
```

#### 关键指标 | Key Metrics
```bash
# 当前 epoch 编号
grep "GetCurrentEpochNumber" logs/seth.log | tail -1

# 最近的总奖励
grep "total_epoch_reward" logs/seth.log | tail -10

# 燃烧的 gas 总量
grep "gas_burned" logs/seth.log | awk '{sum+=$NF} END {print sum}'
```

### 配置调整 | Configuration Adjustment

#### 修改初始奖励 | Modify Initial Reward
```cpp
// src/common/utils.h
static const uint64_t kInitialBlockReward = 500llu * kSethMiniTransportUnit;  // 改为 500 SETH
```

#### 修改减半周期 | Modify Halving Period
```cpp
// src/common/utils.h
static const uint32_t kHalvingPeriodEpochs = 525600u;  // 改为 2 年
```

#### 修改燃烧比例 | Modify Burn Ratio
```cpp
// src/common/utils.h
static const double kBurnRatio = 0.3;  // 改为 30%
```

### 常见问题 | FAQ

#### Q1: 如何验证减半是否正常工作？
**A1**: 查看日志中的 `halving_count` 和 `base_reward`，确认每 262,800 个 epoch 奖励减半。

#### Q1: How to verify halving works correctly?
**A1**: Check `halving_count` and `base_reward` in logs, confirm reward halves every 262,800 epochs.

---

#### Q2: 燃烧的代币去哪了？
**A2**: 燃烧的代币不会分配给任何人，相当于从流通中永久移除，减少总供应量。

#### Q2: Where do burned tokens go?
**A2**: Burned tokens are not distributed to anyone, effectively removed from circulation permanently, reducing total supply.

---

#### Q3: 如何回退到旧的奖励模型？
**A3**: 修改 `GetMiningMaxCount()` 函数，恢复原来的计算公式：
```cpp
auto now_ming_count = common::kMiningTokenMultiplicationFactor * 
                      log2((double)max_tx_count) * 
                      common::kSethMiniTransportUnit;
return now_ming_count;
```

#### Q3: How to rollback to old reward model?
**A3**: Modify `GetMiningMaxCount()` function, restore original formula:
```cpp
auto now_ming_count = common::kMiningTokenMultiplicationFactor * 
                      log2((double)max_tx_count) * 
                      common::kSethMiniTransportUnit;
return now_ming_count;
```

---

#### Q4: 质押奖励池什么时候启用？
**A4**: 当前质押奖励池已计算但未分配，等待质押机制实现后启用。可以暂时将 `kStakingRewardRatio` 设为 0。

#### Q4: When will staking reward pool be activated?
**A4**: Staking pool is calculated but not distributed yet, waiting for staking mechanism implementation. Can temporarily set `kStakingRewardRatio` to 0.

---

#### Q5: 性能影响有多大？
**A5**: 新增计算非常轻量（几次乘除法和一次对数运算），对性能影响可忽略不计（< 0.1ms）。

#### Q5: What's the performance impact?
**A5**: New calculations are very lightweight (few multiplications/divisions and one logarithm), negligible performance impact (< 0.1ms).

---

### 测试检查清单 | Testing Checklist

- [ ] 单元测试：减半机制
- [ ] 单元测试：最小奖励保护
- [ ] 单元测试：燃烧机制
- [ ] 单元测试：边界条件（epoch 0, 溢出等）
- [ ] 集成测试：多个 epoch 运行
- [ ] 集成测试：不同交易量场景
- [ ] 集成测试：与 FTS 分配兼容性
- [ ] 性能测试：计算开销
- [ ] 性能测试：高负载场景
- [ ] 日志验证：所有关键路径有日志
- [ ] 监控验证：指标正确采集

---

### 联系方式 | Contact

如有问题或建议，请联系开发团队。

For questions or suggestions, please contact the development team.

---

**版本 | Version**: v1.0  
**更新日期 | Last Updated**: 2026-04-15
