# FTS 滞留罚分机制详解

## 概述

Seth 区块链的 FTS（Fair Transaction Selection）共识算法中包含了一个创新的**滞留罚分机制**（Consensus Gap Penalty），用于防止节点长期占据选举位置，确保网络的公平性和去中心化。

## 核心思想

滞留罚分机制的核心思想是：**节点在选举池中停留的时间越长，其选举权重会逐渐降低**，从而给新节点和其他节点更多的机会参与共识，防止少数节点垄断网络。

## 机制详解

### 1. Consensus Gap 的定义

`consensus_gap` 是一个累积计数器，记录节点**连续参与共识的次数**：

```cpp
// 每次节点参与共识时，consensus_gap 递增
accoutPoceInfoIterm->consensus_gap += 1;
```

**关键特性：**
- 初始值：新加入的节点 `consensus_gap = 0`
- 累积规则：每参与一次共识（进入选举池），计数器 +1
- 持久化：该值会被持久化到账户信息中，跨 epoch 保留

### 2. 在 FTS 计算中的作用

在 FTS 算法的五维度评分系统中，`consensus_gap` 作为**第五个维度**参与计算：

```cpp
// FTS 最终得分计算公式
elect_nodes[i]->fts_value = (2 * ip_weight[i] +        // 20% - 地理位置权重
                             2 * credit_weight[i] +     // 20% - 信用权重
                             2 * blance_weight[i] +     // 20% - 质押权重
                             2 * epoch_weight[i]) +     // 20% - 工作量权重
                             2 * gap_weight[i] /        // 20% - 滞留罚分
                            10;
```

**注意：** `gap_weight` 的计算方式与其他维度相同，都经过归一化处理，但在最终公式中被除以 10，这意味着：
- **滞留罚分的实际权重约为 2%**（而非 20%）
- 这是一个温和的惩罚机制，不会过度影响节点的选举机会

### 3. Gap Weight 的归一化处理

与其他维度一样，`gap_weight` 也经过归一化处理：

```cpp
std::vector<int32_t> gap_weight;
gap_weight.resize(elect_nodes.size(), 0);
int32_t min_gap_weight = (std::numeric_limits<int32_t>::max)();
int32_t max_gap_weight = (std::numeric_limits<int32_t>::min)();

// 找出最大和最小的 consensus_gap
for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
    gap_weight[i] = elect_nodes[i]->consensus_gap;
    if (gap_weight[i] > max_gap_weight) {
        max_gap_weight = gap_weight[i];
    }
    if (gap_weight[i] < min_gap_weight) {
        min_gap_weight = gap_weight[i];
    }
}

// 归一化到 [min_balance, max_balance] 区间
int32_t weight_diff = max_gap_weight - min_gap_weight;
if (weight_diff > 0) {
    int32_t weight_index = blance_diff / weight_diff;
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        gap_weight[i] = min_balance + weight_index * (gap_weight[i] - min_gap_weight);
    }
}
```

**归一化效果：**
- 将所有节点的 `consensus_gap` 映射到统一的权重区间
- `consensus_gap` 越大的节点，`gap_weight` 越高
- 但在最终 FTS 计算中，`gap_weight` 越高意味着得分越低（因为是罚分）

### 4. 滞留罚分的实际影响

#### 场景分析

假设一个分片有 1024 个节点：

**节点 A（老节点）：**
- 已连续参与 50 次共识
- `consensus_gap = 50`
- 归一化后 `gap_weight = 1000`（假设）
- FTS 罚分：`2 * 1000 / 10 = 200`

**节点 B（新节点）：**
- 刚加入选举池
- `consensus_gap = 0`
- 归一化后 `gap_weight = 0`
- FTS 罚分：`2 * 0 / 10 = 0`

**结果：** 节点 B 比节点 A 在 FTS 得分上高出 200 分，增加了被选中的概率。

#### 长期效应

随着时间推移：
1. **老节点逐渐被淘汰**：连续参与共识的节点，`consensus_gap` 不断增加，FTS 得分逐渐降低
2. **新节点获得机会**：新加入的节点 `consensus_gap = 0`，在其他条件相同时更容易被选中
3. **自然轮换**：即使是高质押、高信用的节点，也会因为滞留罚分而最终被轮换出去

### 5. 与淘汰机制的配合

滞留罚分与 Seth 的 10% 淘汰机制配合使用：

```cpp
// 每个 epoch 淘汰 10% 的节点（每分片 102 个）
std::set<uint32_t> weedout_nodes;
FtsGetNodes(elect_nodes_to_choose, true, weed_out_count - invalid_nodes.size(), weedout_nodes);
```

**配合效果：**
- **淘汰机制**：每 10 分钟强制淘汰 FTS 得分最低的 10% 节点
- **滞留罚分**：确保长期占据选举池的节点逐渐进入淘汰名单
- **公平轮换**：即使是表现优秀的节点，也会因为滞留时间过长而被淘汰，给其他节点机会

## 设计优势

### 1. 防止垄断

传统 PoS 系统中，富人可以通过大量质押长期垄断网络。Seth 的滞留罚分机制确保：
- 即使是高质押节点，也会因为滞留时间过长而被淘汰
- 新节点和小节点有机会参与共识

### 2. 促进去中心化

通过强制轮换机制：
- 网络中的共识节点不断变化
- 没有节点可以永久占据选举位置
- 增加了攻击者控制网络的难度

### 3. 激励节点活跃

节点被淘汰后，`consensus_gap` 会重置为 0（当节点重新加入时），这激励节点：
- 主动退出并重新加入，保持活跃
- 不断提升其他维度的表现（质押、工作量、信用等）

### 4. 温和的惩罚

滞留罚分的权重仅为 2%（`2 * gap_weight / 10`），这意味着：
- 不会过度惩罚表现优秀的节点
- 给予节点足够的时间积累奖励
- 平衡了公平性和稳定性

## 与其他机制的对比

### 传统 PoS

| 特性 | 传统 PoS | Seth FTS + 滞留罚分 |
|------|----------|---------------------|
| 选举依据 | 质押量 | 五维度综合评分 |
| 长期占据 | 可能 | 不可能（滞留罚分） |
| 新节点机会 | 少 | 多（gap = 0 优势） |
| 去中心化 | 中等 | 高（强制轮换） |
| 富人垄断 | 容易 | 困难（多维度+罚分） |

### 传统 PoW

| 特性 | 传统 PoW | Seth FTS + 滞留罚分 |
|------|----------|---------------------|
| 能源消耗 | 高 | 低 |
| 选举公平性 | 高（算力） | 高（多维度+罚分） |
| 长期占据 | 不可能 | 不可能 |
| 新节点机会 | 取决于算力 | 多（gap = 0 优势） |

## 代码实现位置

### 核心文件

1. **`src/pools/shard_statistic.cc`**
   - Line 376: `consensus_gap` 递增逻辑
   - Line 1028: `consensus_gap` 统计收集

2. **`src/consensus/zbft/elect_tx_item.cc`**
   - Line 1031: 从统计数据读取 `consensus_gap`
   - Line 1307-1333: `gap_weight` 归一化处理
   - Line 1363-1369: FTS 最终得分计算（包含滞留罚分）

3. **`src/protos/address.proto`**
   - `consensus_gap` 字段定义（持久化到账户信息）

4. **`src/protos/pools.proto`**
   - `consensus_gap` 在统计数据中的定义

## 总结

Seth 的滞留罚分机制是 FTS 混合共识算法的重要组成部分，它通过温和但持续的惩罚，确保了：

1. **公平性**：防止少数节点长期垄断网络
2. **去中心化**：强制节点轮换，增加网络的去中心化程度
3. **安全性**：增加了攻击者控制网络的难度
4. **活跃性**：激励节点保持活跃，不断提升表现

这个机制与 FTS 的其他四个维度（地理位置、信用、质押、工作量）以及 BLS 阈值签名随机性、10% 淘汰机制共同构成了 Seth 独特的混合共识系统，实现了**公平、安全、高效**的区块链网络。

---

**相关文档：**
- [FTS 混合共识经济模型](SETH_HYBRID_CONSENSUS_ECONOMIC_MODEL.md)
- [FTS 随机性与 BLS 阈值签名](FTS_RANDOMNESS_AND_BLS.md)
- [FTS vs PoS 对比分析](FTS_VS_POS_COMPARISON.md)
- [经济模型总结](ECONOMIC_MODEL_SUMMARY.md)
