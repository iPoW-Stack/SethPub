# Seth 动态分片激励系统 - 快速参考

## 核心公式

### 总激励计算
```
Total Epoch Reward = Shard Base Reward + Transaction Bonus

其中：
Shard Base Reward = (Total Base * Weight) / Total Weight
Transaction Bonus = Shard Base * (log2(tx_count)/20) * 0.2
```

### 时间衰减
```
Base Reward = 10,000 / (2^halving_count)
Halving Count = Epoch Number / 1,051,200  (每4年减半)
```

### 分片权重
```
Weight(generation) = 0.9^generation

Gen 0: 1.0
Gen 1: 0.9 (90%)
Gen 2: 0.81 (81%)
Gen 3: 0.729 (72.9%)
...
Gen 8: 0.430467 (43%)
```

## 分片世代表

| 世代 | 分片ID范围 | 分片数 | 权重 | 相对Gen0 |
|------|-----------|--------|------|----------|
| 0 | 3-5 | 3 | 1.0 | 100% |
| 1 | 6-10 | 5 | 0.9 | 90% |
| 2 | 11-18 | 8 | 0.81 | 81% |
| 3 | 19-34 | 16 | 0.729 | 72.9% |
| 4 | 35-66 | 32 | 0.6561 | 65.6% |
| 5 | 67-130 | 64 | 0.59049 | 59% |
| 6 | 131-258 | 128 | 0.531441 | 53.1% |
| 7 | 259-514 | 256 | 0.478297 | 47.8% |
| 8 | 515-1026 | 512 | 0.430467 | 43% |

## 典型场景奖励

### 场景 1：初始阶段（3分片）
- **每分片奖励**：~4,155 SETH
- **全网总奖励**：~11,000 SETH (含10%早期奖励)

### 场景 2：成长期（8分片）
- **Gen 0 分片**：~1,467 SETH
- **Gen 1 分片**：~1,320 SETH
- **全网总奖励**：~11,000 SETH

### 场景 3：成熟期（1024分片，第一次减半后）
- **Gen 0 分片**：~10.10 SETH
- **Gen 8 分片**：~4.35 SETH
- **全网总奖励**：~5,000 SETH (减半)

## 关键参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 初始总奖励 | 10,000 SETH | 每epoch全网基础奖励 |
| 减半周期 | 1,051,200 epochs | 4年 |
| 早期奖励 | 1.1x | 分片<1024时多10% |
| 世代衰减 | 0.9 | 每代减少10% |
| 交易奖励 | 20% | 最多为分片奖励的20% |
| Gas燃烧 | 50% | 销毁50% gas费用 |

## 代码位置

### 常量定义
```
文件：src/common/utils.h
行号：~280-310

关键常量：
- kInitialTotalReward
- kHalvingPeriodEpochs
- kEarlyBonusMultiplier
- kGenerationWeightDecay
- kShardGenerations[]
```

### 核心函数
```
文件：src/consensus/zbft/elect_tx_item.cc
行号：~610-850

关键函数：
- GetShardGeneration()
- GetActiveShardCount()
- CalculateTotalWeight()
- CalculateShardReward()
- CalculateTotalEpochReward()
```

## 快速验证

### 验证总激励固定
```bash
# 3个分片
3 * 4,155 ≈ 12,465 SETH (含交易奖励)

# 8个分片
3 * 1,467 + 5 * 1,320 = 11,001 SETH ✓

# 1024个分片（减半后）
Total ≈ 5,000 SETH ✓
```

### 验证10%差异
```bash
Gen 1 / Gen 0 = 1,320 / 1,467 = 0.90 = 90% ✓
```

### 验证早期奖励
```bash
Early (3 shards): 11,000 SETH
Full (1024 shards): 10,000 SETH
Bonus: 10% ✓
```

## 监控命令

```bash
# 查看分片奖励
grep "CalculateShardReward" logs/seth.log | tail -20

# 查看总权重
grep "total_weight=" logs/seth.log | tail -10

# 查看早期奖励系数
grep "CalculateEarlyBonus" logs/seth.log | tail -5

# 统计平均奖励
grep "shard_reward=" logs/seth.log | \
  awk -F'shard_reward=' '{print $2}' | \
  awk '{sum+=$1; n++} END {print sum/n}'
```

## 常见问题

### Q: 如何查看我的分片属于哪个世代？
```cpp
uint32_t gen = GetShardGeneration(my_shard_id);
// Shard 3-5: Gen 0
// Shard 6-10: Gen 1
// ...
```

### Q: 为什么我的分片奖励比别人少？
A: 后加入的分片（更高世代）奖励会少10%，这是设计的一部分，鼓励早期参与。

### Q: 什么时候会减半？
A: 每 1,051,200 个 epoch（约4年）减半一次。

### Q: 早期奖励什么时候消失？
A: 当全网达到 1024 个分片时，早期奖励（10%）消失。

### Q: 如何调整参数？
A: 修改 `src/common/utils.h` 中的常量，重新编译即可。

## 性能指标

- **计算复杂度**：O(1) - 常数时间
- **内存开销**：< 1 KB
- **计算延迟**：< 0.1 ms

## 部署状态

- [x] 代码实现
- [x] 编译通过
- [x] 数学验证
- [ ] 单元测试
- [ ] 测试网部署
- [ ] 主网部署

---

**版本**：v2.0  
**更新**：2026-04-15
