# Seth 经济模型设计文档 (Seth Economic Model Design)

## 1. 当前系统分析 (Current System Analysis)

### 1.1 现有奖励机制 (Existing Reward Mechanism)

当前 Seth 的挖矿奖励计算公式：

```cpp
// 每轮最大奖励计算
now_ming_count = kMiningTokenMultiplicationFactor * log2(max_tx_count) * kSethMiniTransportUnit

// 单个节点奖励分配
mining_token = now_ming_count * tx_count / max_tx_count
total_reward = mining_token + gas_token
```

**关键参数：**
- `kMiningTokenMultiplicationFactor = 1.0` - 挖矿倍数因子
- `kSethMiniTransportUnit = 100000000` (10^8) - 最小单位
- `kSethMaxAmount = 2100 * 10^8 * 10^8` - 总供应量 (21亿亿)
- `kTimeBlockCreatePeriodSeconds = 120` - 时间块周期 (120秒)
- `kRotationPeriod = 120 * 10^6` - 轮换周期 (120秒，微秒单位)

**问题：**
1. 奖励仅基于交易数量的对数，没有考虑区块高度或时间
2. 没有通胀控制机制
3. 没有减半或衰减机制
4. 总供应量可能过早耗尽

### 1.2 系统架构参数 (System Architecture Parameters)

- **分片数量**: 最多 1024 个分片
- **每分片节点**: 最多 1024 个节点
- **每分片 TPS**: 2000 TPS
- **理论最大 TPS**: 2,048,000 TPS
- **轮换周期**: 120 秒 (每个 epoch)
- **淘汰率**: 10% 节点每轮淘汰

## 2. 以太坊经济模型参考 (Ethereum Economic Model Reference)

### 2.1 以太坊 2.0 (PoS) 奖励机制

以太坊 2.0 的奖励公式：

```
年化奖励率 = C / sqrt(总质押量)
```

其中 C 是常数，确保：
- 质押量低时，奖励率高，吸引更多质押
- 质押量高时，奖励率低，避免过度通胀

### 2.2 EIP-1559 燃烧机制

- **基础费用 (Base Fee)**: 根据网络拥堵动态调整
- **燃烧机制**: 基础费用被销毁，减少供应
- **小费 (Priority Fee)**: 给予矿工/验证者

### 2.3 比特币减半机制

- 每 210,000 个区块减半一次
- 初始奖励: 50 BTC
- 当前奖励: 6.25 BTC (2020年减半后)
- 总供应量: 2100万 BTC

## 3. Seth 新经济模型设计 (New Economic Model for Seth)

### 3.1 设计目标 (Design Goals)

1. **可持续性**: 确保奖励可持续发放，不会过早耗尽
2. **通胀控制**: 合理控制通胀率，保护代币价值
3. **激励对齐**: 激励节点长期参与网络
4. **公平分配**: 基于贡献公平分配奖励
5. **兼容性**: 保持与现有分配算法的兼容

### 3.2 混合奖励模型 (Hybrid Reward Model)

结合以太坊和比特币的优点，设计混合模型：

#### 3.2.1 基础奖励 (Base Reward)

采用类似比特币的减半机制，但周期更短：

```
epoch_number = (current_timestamp - first_timeblock_timestamp) / kTimeBlockCreatePeriodSeconds
halving_count = epoch_number / HALVING_PERIOD
base_reward = INITIAL_REWARD / (2 ^ halving_count)
```

**参数建议：**
- `INITIAL_REWARD = 1000 * kSethMiniTransportUnit` (1000 SETH)
- `HALVING_PERIOD = 262800` (约1年，假设120秒一个epoch)
  - 计算: 365.25 * 24 * 3600 / 120 ≈ 262800 epochs/year

#### 3.2.2 交易奖励 (Transaction Reward)

保留现有的基于交易量的奖励，但作为补充：

```
tx_reward_factor = log2(max_tx_count + 1) / 20.0  // 归一化到 0-1
tx_bonus = base_reward * tx_reward_factor * TX_BONUS_MULTIPLIER
```

**参数建议：**
- `TX_BONUS_MULTIPLIER = 0.5` (交易奖励最多为基础奖励的50%)

#### 3.2.3 质押奖励 (Staking Reward)

基于节点质押量的额外奖励：

```
total_staked = sum(all_node_stakes)
staking_reward_pool = base_reward * STAKING_REWARD_RATIO
node_staking_reward = staking_reward_pool * (node_stake / total_staked)
```

**参数建议：**
- `STAKING_REWARD_RATIO = 0.3` (质押奖励占基础奖励的30%)

#### 3.2.4 总奖励计算 (Total Reward Calculation)

```
total_epoch_reward = base_reward + tx_bonus + staking_reward_pool
```

### 3.3 燃烧机制 (Burn Mechanism)

参考 EIP-1559，引入部分燃烧：

```
gas_to_burn = total_gas_collected * BURN_RATIO
gas_to_distribute = total_gas_collected - gas_to_burn
```

**参数建议：**
- `BURN_RATIO = 0.5` (50% gas 被销毁)

### 3.4 通胀率分析 (Inflation Rate Analysis)

#### 初始阶段 (第1年)
- 每 epoch 奖励: 1000 SETH
- 每年 epochs: 262,800
- 年产出: 262,800,000 SETH
- 初始通胀率: ~1.25% (假设初始流通 210亿)

#### 第2年 (第一次减半后)
- 每 epoch 奖励: 500 SETH
- 年产出: 131,400,000 SETH
- 通胀率: ~0.62%

#### 长期 (10年后)
- 累计减半: 10次
- 每 epoch 奖励: ~0.98 SETH
- 年产出: ~257,544 SETH
- 通胀率: ~0.001%

### 3.5 供应量预测 (Supply Projection)

总供应量: 21,000,000,000,000,000 (2100万亿)

**挖矿产出预测：**
```
Year 1:   262,800,000 SETH
Year 2:   131,400,000 SETH
Year 3:    65,700,000 SETH
Year 4:    32,850,000 SETH
Year 5:    16,425,000 SETH
...
Total (100 years): ~525,600,000 SETH (仅占总供应量的 0.0025%)
```

**结论**: 即使100年，挖矿产出也不会显著影响总供应量。

## 4. 实现方案 (Implementation Plan)

### 4.1 修改文件 (Files to Modify)

1. **src/common/utils.h**
   - 添加新的经济模型常量

2. **src/consensus/zbft/elect_tx_item.h**
   - 添加新的成员变量和方法声明

3. **src/consensus/zbft/elect_tx_item.cc**
   - 修改 `GetMiningMaxCount()` 函数
   - 修改 `MiningToken()` 函数
   - 添加新的辅助函数

### 4.2 新增常量 (New Constants)

```cpp
// Economic Model Parameters
static const uint64_t kInitialBlockReward = 1000llu * kSethMiniTransportUnit;
static const uint32_t kHalvingPeriodEpochs = 262800u;  // ~1 year
static const double kTxBonusMultiplier = 0.5;
static const double kStakingRewardRatio = 0.3;
static const double kBurnRatio = 0.5;
static const uint64_t kMinBlockReward = 1llu * kSethMiniTransportUnit;  // 最小奖励
```

### 4.3 新增函数 (New Functions)

```cpp
// 计算当前 epoch 编号
uint64_t GetCurrentEpochNumber();

// 计算基础奖励（考虑减半）
uint64_t CalculateBaseReward(uint64_t epoch_number);

// 计算交易奖励加成
uint64_t CalculateTxBonus(uint64_t base_reward, uint64_t max_tx_count);

// 计算质押奖励池
uint64_t CalculateStakingRewardPool(uint64_t base_reward);

// 计算总 epoch 奖励
uint64_t CalculateTotalEpochReward(uint64_t max_tx_count);

// 应用燃烧机制
void ApplyBurnMechanism(uint64_t total_gas, uint64_t* gas_to_distribute, uint64_t* gas_to_burn);
```

### 4.4 修改流程 (Modified Flow)

```
1. GetCurrentEpochNumber() 
   ↓
2. CalculateBaseReward(epoch_number)
   ↓
3. CalculateTxBonus(base_reward, max_tx_count)
   ↓
4. CalculateStakingRewardPool(base_reward)
   ↓
5. CalculateTotalEpochReward() = base_reward + tx_bonus + staking_pool
   ↓
6. 使用现有的 FTS 算法分配 total_epoch_reward
   ↓
7. ApplyBurnMechanism() 处理 gas 费用
   ↓
8. 分配最终奖励给各节点
```

## 5. 配置参数 (Configuration Parameters)

建议添加配置文件支持，允许动态调整参数：

```json
{
  "economic_model": {
    "initial_block_reward": 1000,
    "halving_period_epochs": 262800,
    "tx_bonus_multiplier": 0.5,
    "staking_reward_ratio": 0.3,
    "burn_ratio": 0.5,
    "min_block_reward": 1,
    "enable_halving": true,
    "enable_burn": true
  }
}
```

## 6. 测试计划 (Testing Plan)

### 6.1 单元测试
- 测试减半机制正确性
- 测试奖励计算准确性
- 测试边界条件（最小奖励、溢出等）

### 6.2 集成测试
- 测试与现有分配算法的兼容性
- 测试多个 epoch 的奖励变化
- 测试燃烧机制

### 6.3 性能测试
- 测试计算开销
- 测试大规模节点场景

## 7. 风险与缓解 (Risks and Mitigation)

### 7.1 风险
1. **参数选择不当**: 可能导致通胀过高或奖励不足
2. **兼容性问题**: 可能影响现有节点
3. **经济攻击**: 可能被恶意利用

### 7.2 缓解措施
1. **参数可配置**: 允许通过配置文件调整
2. **渐进式部署**: 先在测试网验证
3. **监控机制**: 实时监控通胀率和奖励分配
4. **应急方案**: 保留回退到旧模型的能力

## 8. 部署计划 (Deployment Plan)

### 阶段 1: 开发与测试 (2周)
- 实现新经济模型
- 编写单元测试
- 代码审查

### 阶段 2: 测试网部署 (4周)
- 部署到测试网
- 监控运行数据
- 收集社区反馈
- 调整参数

### 阶段 3: 主网部署 (2周)
- 准备主网升级
- 社区投票
- 执行升级
- 持续监控

## 9. 总结 (Summary)

新经济模型的核心优势：

1. **可持续性**: 减半机制确保长期可持续
2. **灵活性**: 多种奖励来源，适应不同场景
3. **通缩性**: 燃烧机制减少供应，支撑价值
4. **兼容性**: 保留现有分配算法，平滑过渡
5. **可配置**: 参数可调整，适应市场变化

通过引入类似以太坊的经济模型，Seth 将拥有更加健康和可持续的代币经济系统。
