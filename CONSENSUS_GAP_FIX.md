# Consensus Gap 逻辑修复说明

## 问题描述

`consensus_gap` 因子的归一化逻辑存在错误，导致与设计意图相反的行为。

### 原始问题

**设计意图：** 节点滞留越久（连续多轮被选中），应该被罚分，降低其再次被选中的概率，促进委员会成员轮换。

**实际行为（修复前）：**
- 节点每次被选入委员会时，`consensus_gap += 1`（shard_statistic.cc:394）
- 归一化时：`gap_weight[i] = 100 + (consensus_gap[i] - min) * 9900 / (max - min)`
- 结果：**consensus_gap 越大 → gap_weight 越大 → FTS 越高 → 越容易被选中**
- 这形成了**正反馈循环**（富者愈富），与设计意图相反

## 修复方案

### 反转归一化公式

将 `gap_weight` 的归一化逻辑反转，使 `consensus_gap` 越大的节点得分越低：

```cpp
// 修复前（错误）：
gap_weight[i] = 100 + (gap_weight[i] - min_gap_weight) * 9900 / (max_gap_weight - min_gap_weight);
// consensus_gap 最大 → gap_weight = 10000（最高分）

// 修复后（正确）：
gap_weight[i] = 10000 - (gap_weight[i] - min_gap_weight) * 9900 / (max_gap_weight - min_gap_weight);
// consensus_gap 最大 → gap_weight = 100（最低分）
// consensus_gap 最小 → gap_weight = 10000（最高分）
```

### 修复后的逻辑流程

1. **累加阶段（shard_statistic.cc:394）：**
   ```cpp
   for(auto node : elect_block.in()) {
       accoutPoceInfoIterm->consensus_gap += 1;  // 被选中的节点 +1
   }
   ```

2. **归一化阶段（elect_tx_item.cc:1483-1486）：**
   ```cpp
   // 反转公式：max_gap → 100, min_gap → 10000
   gap_weight[i] = 10000 - (gap_weight[i] - min_gap_weight) * 9900 / (max_gap_weight - min_gap_weight);
   ```

3. **FTS 计算（elect_tx_item.cc:1525-1529）：**
   ```cpp
   elect_nodes[i]->fts_value = (2 * credit_weight[i] +
                                2 * pos_weight[i] +
                                2 * epoch_weight[i] +
                                2 * area_weight_smooth[i] +
                                2 * gap_weight[i]);  // gap_weight 越低，FTS 越低
   ```

### 效果示例

假设有 3 个节点：
- 节点 A：`consensus_gap = 10`（老节点，连续被选中 10 次）
- 节点 B：`consensus_gap = 5`（中等）
- 节点 C：`consensus_gap = 1`（新节点，刚被选中 1 次）

**修复前（错误）：**
- 节点 A：`gap_weight = 10000`（最高分，最容易被选中）
- 节点 B：`gap_weight = 5500`
- 节点 C：`gap_weight = 100`（最低分，最难被选中）

**修复后（正确）：**
- 节点 A：`gap_weight = 100`（最低分，最难被选中）✅ 罚分
- 节点 B：`gap_weight = 5500`
- 节点 C：`gap_weight = 10000`（最高分，最容易被选中）✅ 促进新节点

## 修改文件

- **src/consensus/zbft/elect_tx_item.cc** (lines 1460-1495)
  - 反转 `gap_weight` 归一化公式
  - 添加详细注释说明反转逻辑
  - 当所有节点 `consensus_gap` 相同时，使用中间值 5050

## 验证要点

1. ✅ **负反馈机制：** 节点滞留越久 → gap_weight 越低 → FTS 越低 → 被淘汰概率越高
2. ✅ **促进轮换：** 新节点或短期节点获得更高的 gap_weight，更容易被选中
3. ✅ **独立归一化：** gap_weight 仍然独立归一化到 [100, 10000]，不影响其他因子
4. ✅ **权重平衡：** gap_weight 在 FTS 中的权重仍为 2x，与其他因子相同

## 语义说明

**consensus_gap 的含义：**
- 表示节点**累计被选入委员会的次数**
- 每次选举时，被选中的节点 `consensus_gap += 1`
- 值越大 = 滞留时间越长 = 应该被罚分（降低选举概率）

**gap_weight 的含义（修复后）：**
- 表示节点在"轮换促进"维度的得分
- 值越高 = 越应该被选中（新节点或短期节点）
- 值越低 = 越应该被淘汰（老节点或长期节点）

## 相关代码位置

- **累加逻辑：** `src/pools/shard_statistic.cc:394`
- **归一化逻辑：** `src/consensus/zbft/elect_tx_item.cc:1460-1495`
- **FTS 计算：** `src/consensus/zbft/elect_tx_item.cc:1525-1529`
- **淘汰逻辑：** `src/consensus/zbft/elect_tx_item.cc:1300-1350` (CheckWeedout)

## 总结

此修复确保了 `consensus_gap` 因子按照设计意图工作：
- ✅ 滞留越久的节点被罚分
- ✅ 促进委员会成员轮换
- ✅ 避免"富者愈富"的正反馈循环
- ✅ 保持 FTS 算法的公平性和去中心化特性
