# Credit Weight 计算流程分析

## 概述

`credit_weight` 是 FTS 算法中的一个重要因子，用于衡量节点的**历史贡献度**。本文档详细梳理其计算流程。

## ✅ 当前实现：正确累积历史贡献度

### 数据流程图

```
第 N 轮选举
    ↓
elect_block.in() (被选中的节点)
    ↓
accout_poce_info_map_[addr]->credit += node.fts_value()  [累加]
    ↓
第 N+1 轮选举统计
    ↓
statistic_item.add_credit(node_poce_info->credit)  [读取累积值]
    ↓
elect_statistic.statistics[i].credit(member_idx)
    ↓
node_info->credit = statistic_item.credit(member_idx)
    ↓
credit_weight[i] = elect_nodes[i]->credit
    ↓
归一化到 [100, 10000]
    ↓
FTS 计算：2 * credit_weight[i]
```

## 详细流程分析

### 1. Credit 累加阶段（shard_statistic.cc:395）

**触发时机：** 每次有新的选举区块（elect_block）产生时

**代码位置：** `src/pools/shard_statistic.cc:385-400`

```cpp
if (block.has_elect_block()) {
    auto& elect_block = block.elect_block();
    
    for(auto node : elect_block.in()) {
        auto addr = secptr_->GetAddressWithPublicKey(node.pubkey());
        auto acc_iter = accout_poce_info_map_.find(addr);
        if (acc_iter == accout_poce_info_map_.end()) {
            accout_poce_info_map_[addr] = std::make_shared<AccoutPoceInfoItem>();
            acc_iter = accout_poce_info_map_.find(addr);
        }

        auto& accoutPoceInfoIterm = acc_iter->second;
        accoutPoceInfoIterm->consensus_gap += 1;
        accoutPoceInfoIterm->credit += node.fts_value();  // ⭐ 累加 FTS 值
    }
}
```

**关键点：**
- ✅ `elect_block.in()` 包含**本轮被选中的所有节点**
- ✅ 每个被选中的节点，其 `credit` 累加本轮的 `fts_value`
- ✅ `fts_value` 是该节点在本轮选举中的综合得分（包含 pos、epoch、area、gap 等因子）
- ✅ 使用 `+=` 运算符，**持续累积**，不会被重置

**累加的值：**
```cpp
node.fts_value()  // 本轮选举中该节点的 FTS 总分
```

FTS 总分范围：[1000, 100000]（5 个因子，每个 [100, 10000]，权重 2x）

### 2. Credit 存储结构（tx_utils.h:115-118）

**代码位置：** `src/pools/tx_utils.h:115-118`

```cpp
struct AccoutPoceInfoItem {
    uint64_t consensus_gap; // 边缘化程度 P
    uint64_t credit;        // 历史贡献度累积值
};
```

**存储位置：** `ShardStatistic::accout_poce_info_map_`

```cpp
std::map<std::string, std::shared_ptr<AccoutPoceInfoItem>> accout_poce_info_map_;
```

**关键特性：**
- ✅ **内存持久化：** `accout_poce_info_map_` 是 `ShardStatistic` 类的成员变量
- ✅ **不会被清空：** 代码中没有 `clear()` 或 `erase()` 操作
- ✅ **跨轮累积：** 每轮选举都在同一个 map 上累加
- ✅ **按地址索引：** 使用节点地址作为 key，确保同一节点的 credit 持续累积

### 3. Credit 读取阶段（shard_statistic.cc:1046）

**触发时机：** 准备下一轮选举统计时

**代码位置：** `src/pools/shard_statistic.cc:1040-1048`

```cpp
for (uint32_t midx = 0; midx < members->size(); ++midx) {
    auto &id = (*members)[midx]->id;
    auto node_info = node_info_map.emplace(id, StatisticMemberInfoItem()).first->second;
    auto node_poce_info = accout_poce_info_map_.try_emplace(
        id, std::make_shared<AccoutPoceInfoItem>()).first->second;
    
    statistic_item.add_credit(node_poce_info->credit);  // ⭐ 读取累积的 credit
    statistic_item.add_consensus_gap(node_poce_info->consensus_gap);
    statistic_item.add_tx_count(node_info.tx_count);
    statistic_item.add_gas_sum(node_info.gas_sum);
    // ...
}
```

**关键点：**
- ✅ 使用 `try_emplace`，如果节点不存在则创建（credit 初始为 0）
- ✅ 读取的是**累积值**，不是单轮值
- ✅ 新节点的 credit 为 0（刚创建时）

### 4. Credit 传递到选举逻辑（elect_tx_item.cc:1163）

**代码位置：** `src/consensus/zbft/elect_tx_item.cc:1163`

```cpp
auto node_info = std::make_shared<ElectNodeInfo>();
node_info->gas_sum = statistic_item.gas_sum(member_idx);
node_info->area_weight = area_weight;
node_info->tx_count = statistic_item.tx_count(member_idx);
node_info->stoke = statistic_item.stokes(member_idx);
node_info->credit = statistic_item.credit(member_idx);  // ⭐ 读取 credit
node_info->index = member_idx;
node_info->pubkey = (*members)[member_idx]->pubkey;
node_info->consensus_gap = statistic_item.consensus_gap(member_idx);
```

### 5. Credit 归一化（elect_tx_item.cc:1390-1420）

**代码位置：** `src/consensus/zbft/elect_tx_item.cc:1390-1420`

```cpp
std::vector<int32_t> credit_weight;
{
    credit_weight.resize(elect_nodes.size(), 0);
    int32_t min_credit = (std::numeric_limits<int32_t>::max)();
    int32_t max_credit = (std::numeric_limits<int32_t>::min)();
    
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        credit_weight[i] = elect_nodes[i]->credit;  // ⭐ 使用累积的 credit
        if (min_credit > credit_weight[i]) {
            min_credit = credit_weight[i];
        }
        if (max_credit < credit_weight[i]) {
            max_credit = credit_weight[i];
        }
    }

    // Normalize to [100, 10000]
    if (max_credit > min_credit) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            credit_weight[i] = 100 + (credit_weight[i] - min_credit) * 9900 / (max_credit - min_credit);
        }
    } else {
        // All nodes have same credit
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            credit_weight[i] = 100;
        }
    }
}
```

**归一化逻辑：**
- ✅ **正向映射：** credit 越高 → credit_weight 越高 → FTS 越高
- ✅ **独立归一化：** 不依赖其他因子
- ✅ **范围：** [100, 10000]

### 6. FTS 计算（elect_tx_item.cc:1530）

**代码位置：** `src/consensus/zbft/elect_tx_item.cc:1530-1534`

```cpp
elect_nodes[i]->fts_value = (2 * credit_weight[i] +      // ⭐ credit 权重 2x
                             2 * pos_weight[i] +
                             2 * epoch_weight[i] +
                             2 * area_weight_smooth[i] +
                             2 * gap_weight[i]);
```

## 累积效果示例

### 场景：节点 A 的 credit 累积过程

**初始状态：**
- 节点 A 刚加入网络
- `accout_poce_info_map_[A]->credit = 0`

**第 1 轮选举：**
- 节点 A 被选中，FTS = 50000
- `credit += 50000` → `credit = 50000`

**第 2 轮选举：**
- 节点 A 再次被选中，FTS = 55000
- `credit += 55000` → `credit = 105000`

**第 3 轮选举：**
- 节点 A 再次被选中，FTS = 48000
- `credit += 48000` → `credit = 153000`

**第 4 轮选举统计：**
- 读取 `credit = 153000`（累积值）
- 与其他节点比较归一化

### 多节点对比

假设第 10 轮选举时的 credit 累积情况：

| 节点 | 参与轮数 | 累积 credit | credit_weight | 说明 |
|------|---------|-------------|---------------|------|
| A    | 10 轮   | 500000      | 10000         | 老节点，高贡献 |
| B    | 5 轮    | 250000      | 5050          | 中等贡献 |
| C    | 1 轮    | 50000       | 100           | 新节点，低贡献 |
| D    | 0 轮    | 0           | 100           | 新节点，无贡献 |

**归一化计算：**
```
min_credit = 0
max_credit = 500000
range = 500000

节点 A: credit_weight = 100 + (500000 - 0) * 9900 / 500000 = 100 + 9900 = 10000
节点 B: credit_weight = 100 + (250000 - 0) * 9900 / 500000 = 100 + 4950 = 5050
节点 C: credit_weight = 100 + (50000 - 0) * 9900 / 500000 = 100 + 990 = 1090
节点 D: credit_weight = 100 + (0 - 0) * 9900 / 500000 = 100
```

## 与 consensus_gap 的对比

| 因子 | 含义 | 累积方式 | 归一化方向 | 设计意图 |
|------|------|----------|------------|----------|
| **credit** | 历史贡献度 | 累加 FTS 值 | 正向（高 credit → 高分） | 奖励历史贡献 |
| **consensus_gap** | 滞留时间 | 累加次数 | **反向**（高 gap → 低分） | 促进轮换 |

**两者的平衡：**
- `credit` 奖励长期贡献者（正反馈）
- `consensus_gap` 惩罚长期滞留者（负反馈）
- 两者共同作用，实现**"奖励贡献，促进轮换"**的平衡

## 验证要点

### ✅ 正确实现的特性

1. **持续累积：**
   - ✅ `accout_poce_info_map_` 不会被清空
   - ✅ 使用 `+=` 运算符累加
   - ✅ 跨轮次持久化

2. **累积的是 FTS 值：**
   - ✅ `credit += node.fts_value()`
   - ✅ FTS 值是综合得分，反映节点的整体表现
   - ✅ 每轮累加的值在 [1000, 100000] 范围内

3. **正向激励：**
   - ✅ credit 越高 → credit_weight 越高
   - ✅ 奖励历史贡献大的节点
   - ✅ 鼓励节点长期稳定参与

4. **新节点处理：**
   - ✅ 新节点 credit 初始为 0
   - ✅ 归一化后得到最低分 100
   - ✅ 需要通过其他因子（如 gap_weight）获得竞争力

5. **独立归一化：**
   - ✅ 归一化到 [100, 10000]
   - ✅ 不依赖其他因子
   - ✅ 权重为 2x，与其他因子相同

## 潜在问题与建议

### ⚠️ 潜在问题 1：Credit 无上限增长

**问题描述：**
- `credit` 会无限累积，没有衰减机制
- 老节点的 credit 可能远超新节点（数量级差异）
- 归一化后，新节点永远得最低分 100

**影响：**
- 新节点难以通过 credit 因子获得竞争力
- 完全依赖其他因子（特别是 gap_weight）来平衡

**建议（可选）：**
1. **引入衰减机制：** 每轮 credit 衰减 1%（例如 `credit *= 0.99`）
2. **设置时间窗口：** 只累积最近 N 轮的 credit
3. **对数归一化：** 使用 `log(credit)` 而不是线性归一化

### ⚠️ 潜在问题 2：Credit 与 consensus_gap 的矛盾

**问题描述：**
- 节点被选中越多 → credit 越高（正反馈）
- 节点被选中越多 → consensus_gap 越高（负反馈）
- 两者相互抵消

**当前平衡：**
- 两者权重相同（都是 2x）
- 理论上会相互抵消一部分影响

**建议（可选）：**
- 调整权重比例，例如 `gap_weight` 权重 3x，`credit_weight` 权重 1x
- 或者保持当前设计，让其他因子（pos、epoch、area）起决定性作用

### ✅ 当前设计的合理性

尽管存在上述潜在问题，**当前设计仍然是合理的**：

1. **多因子平衡：** 5 个因子共同作用，单个因子不会完全主导
2. **gap_weight 的负反馈：** 有效限制了老节点的优势
3. **pos_weight 的重要性：** 质押量是更重要的因子
4. **简单可靠：** 累积逻辑简单，不易出错

## 代码位置总结

| 阶段 | 文件 | 行号 | 说明 |
|------|------|------|------|
| Credit 累加 | `src/pools/shard_statistic.cc` | 395 | `credit += node.fts_value()` |
| Credit 存储 | `src/pools/tx_utils.h` | 115-118 | `AccoutPoceInfoItem` 结构体 |
| Credit 读取 | `src/pools/shard_statistic.cc` | 1046 | `add_credit(node_poce_info->credit)` |
| Credit 传递 | `src/consensus/zbft/elect_tx_item.cc` | 1163 | `node_info->credit = ...` |
| Credit 归一化 | `src/consensus/zbft/elect_tx_item.cc` | 1390-1420 | 归一化到 [100, 10000] |
| FTS 计算 | `src/consensus/zbft/elect_tx_item.cc` | 1530 | `2 * credit_weight[i]` |

## 总结

✅ **当前实现正确：** `credit_weight` 确实累积了节点的历史贡献度

**关键特性：**
1. ✅ 持续累积，不会重置
2. ✅ 累积的是 FTS 综合得分
3. ✅ 正向激励（credit 越高，得分越高）
4. ✅ 与 consensus_gap 形成平衡（一正一负）
5. ✅ 独立归一化，权重平衡

**设计意图：**
- 奖励长期稳定贡献的节点
- 与 gap_weight 的负反馈形成平衡
- 鼓励节点持续参与网络共识

**建议：**
- 当前实现已经符合"累积历史贡献度"的设计要求
- 如果需要进一步优化，可以考虑引入衰减机制或调整权重比例
- 但当前设计已经是一个合理的平衡方案
