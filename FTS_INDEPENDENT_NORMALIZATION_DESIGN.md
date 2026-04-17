# FTS 归一化独立计算设计

## 修改说明

将 FTS 计算中所有因子的归一化处理改为独立计算，每个因子都独立映射到 [100, 10000] 范围内，不再依赖 PoS 权重作为归一化标准。

---

## 问题分析

### 原来的问题

**依赖 PoS 权重进行归一化**:
```cpp
// 原来的代码
int32_t pos_diff = max_pos - min_pos;

// 所有因子都依赖 pos_diff 进行归一化
int32_t credit_index = pos_diff / credit_diff;
credit_weight[i] = min_pos + credit_index * (credit_weight[i] - min_credit);

int32_t area_weight_index = pos_diff / area_weight_diff;
area_weight_smooth[i] = min_pos + area_weight_index * (area_weight_smooth[i] - min_area_weight_smooth);

// ... 其他因子也是如此
```

**问题**:
1. ❌ 所有因子的归一化范围受 PoS 权重影响
2. ❌ 如果 PoS 权重差异小，其他因子的归一化范围也会被压缩
3. ❌ 各因子之间不独立，相互影响
4. ❌ 不公平：PoS 权重主导了整个归一化过程

---

## 新的设计

### 独立归一化

**每个因子独立映射到 [100, 10000]**:

```cpp
// 归一化公式
normalized_value = 100 + (raw_value - min_value) * 9900 / (max_value - min_value)
```

**范围**: [100, 10000]
- 最小值: 100
- 最大值: 10000
- 范围: 9900

---

## 实现细节

### 1. PoS 权重归一化

```cpp
// Normalize PoS weight to [100, 10000]
std::vector<int32_t> pos_weight;
{
    pos_weight.resize(elect_nodes.size(), 0);
    pos_weight[0] = 100;
    int32_t min_pos = 100;
    int32_t max_pos = 100;
    auto &g2 = *g2_;
    
    // Calculate raw pos weights based on stoke
    for (uint32_t i = 1; i < elect_nodes.size(); ++i) {
        uint64_t fts_val_diff = elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;
        if (fts_val_diff == 0) {
            pos_weight[i] = pos_weight[i - 1];
        } else {
            // ... 计算逻辑 ...
        }
        
        if (min_pos > pos_weight[i]) {
            min_pos = pos_weight[i];
        }
        if (max_pos < pos_weight[i]) {
            max_pos = pos_weight[i];
        }
    }

    // ⭐ 独立归一化到 [100, 10000]
    if (max_pos > min_pos) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            pos_weight[i] = 100 + (pos_weight[i] - min_pos) * 9900 / (max_pos - min_pos);
        }
    } else {
        // All nodes have same stoke
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            pos_weight[i] = 100;
        }
    }
}
```

**关键点**:
- ✅ 基于 stoke 计算原始权重
- ✅ 独立归一化到 [100, 10000]
- ✅ 如果所有节点 stoke 相同，权重为 100

---

### 2. Credit 权重归一化

```cpp
// Normalize credit weight to [100, 10000]
std::vector<int32_t> credit_weight;
{
    credit_weight.resize(elect_nodes.size(), 0);
    int32_t min_credit = (std::numeric_limits<int32_t>::max)();
    int32_t max_credit = (std::numeric_limits<int32_t>::min)();
    
    // 收集原始 credit 值
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        credit_weight[i] = elect_nodes[i]->credit;
        if (min_credit > credit_weight[i]) {
            min_credit = credit_weight[i];
        }
        if (max_credit < credit_weight[i]) {
            max_credit = credit_weight[i];
        }
    }

    // ⭐ 独立归一化到 [100, 10000]
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

**关键点**:
- ✅ 不依赖 PoS 权重
- ✅ 独立归一化到 [100, 10000]
- ✅ 如果所有节点 credit 相同，权重为 100

---

### 3. Area 权重归一化

```cpp
// Normalize area weight to [100, 10000]
std::vector<int32_t> area_weight_smooth;
{
    area_weight_smooth.resize(elect_nodes.size(), 0);
    int32_t min_area_weight_smooth = (std::numeric_limits<int32_t>::max)();
    int32_t max_area_weight_smooth = (std::numeric_limits<int32_t>::min)();
    
    // 收集原始 area_weight 值
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        int32_t normalized_area = static_cast<int32_t>(
            static_cast<double>(elect_nodes[i]->area_weight) / ElectTxItem::kAreaPenaltyCoefficient);
        area_weight_smooth[i] = normalized_area;
        
        if (area_weight_smooth[i] > max_area_weight_smooth) {
            max_area_weight_smooth = area_weight_smooth[i];
        }
        if (area_weight_smooth[i] < min_area_weight_smooth) {
            min_area_weight_smooth = area_weight_smooth[i];
        }
    }
    
    // ⭐ 独立归一化到 [100, 10000]
    if (max_area_weight_smooth > min_area_weight_smooth) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            area_weight_smooth[i] = 100 + (area_weight_smooth[i] - min_area_weight_smooth) * 9900 / 
                (max_area_weight_smooth - min_area_weight_smooth);
        }
    } else {
        // All nodes have same area weight
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            area_weight_smooth[i] = 100;
        }
    }
}
```

---

### 4. IP 权重归一化

```cpp
// Normalize IP weight to [100, 10000]
std::vector<int32_t> ip_weight;
{
    ip_weight.resize(elect_nodes.size(), 0);
    int32_t min_ip_weight = (std::numeric_limits<int32_t>::max)();
    int32_t max_ip_weight = (std::numeric_limits<int32_t>::min)();
    
    // 使用 area_weight_smooth 作为 IP 权重
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        ip_weight[i] = area_weight_smooth[i];
        
        if (ip_weight[i] > max_ip_weight) {
            max_ip_weight = ip_weight[i];
        }
        if (ip_weight[i] < min_ip_weight) {
            min_ip_weight = ip_weight[i];
        }
    }

    // ⭐ 独立归一化到 [100, 10000]
    if (max_ip_weight > min_ip_weight) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            ip_weight[i] = 100 + (ip_weight[i] - min_ip_weight) * 9900 / (max_ip_weight - min_ip_weight);
        }
    } else {
        // All nodes have same IP weight
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            ip_weight[i] = 100;
        }
    }
}
```

---

### 5. Gap 权重归一化

```cpp
// Normalize gap weight to [100, 10000]
std::vector<int32_t> gap_weight;
{
    gap_weight.resize(elect_nodes.size(), 0);
    int32_t min_gap_weight = (std::numeric_limits<int32_t>::max)();
    int32_t max_gap_weight = (std::numeric_limits<int32_t>::min)();
    
    // 收集原始 consensus_gap 值
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        gap_weight[i] = elect_nodes[i]->consensus_gap;
        
        if (gap_weight[i] > max_gap_weight) {
            max_gap_weight = gap_weight[i];
        }
        if (gap_weight[i] < min_gap_weight) {
            min_gap_weight = gap_weight[i];
        }
    }

    // ⭐ 独立归一化到 [100, 10000]
    if (max_gap_weight > min_gap_weight) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            gap_weight[i] = 100 + (gap_weight[i] - min_gap_weight) * 9900 / (max_gap_weight - min_gap_weight);
        }
    } else {
        // All nodes have same gap weight
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            gap_weight[i] = 100;
        }
    }
}
```

---

### 6. Epoch 权重归一化

```cpp
// Normalize epoch weight to [100, 10000]
std::vector<int32_t> epoch_weight;
{
    epoch_weight.resize(elect_nodes.size(), 0);
    int32_t min_epoch_weight = (std::numeric_limits<int32_t>::max)();
    int32_t max_epoch_weight = (std::numeric_limits<int32_t>::min)();
    
    // 收集原始 tx_count 值
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        epoch_weight[i] = elect_nodes[i]->tx_count;
        
        if (epoch_weight[i] > max_epoch_weight) {
            max_epoch_weight = epoch_weight[i];
        }
        if (epoch_weight[i] < min_epoch_weight) {
            min_epoch_weight = epoch_weight[i];
        }
    }

    // ⭐ 独立归一化到 [100, 10000]
    if (max_epoch_weight > min_epoch_weight) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            epoch_weight[i] = 100 + (epoch_weight[i] - min_epoch_weight) * 9900 / (max_epoch_weight - min_epoch_weight);
        }
    } else {
        // All nodes have same epoch weight
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            epoch_weight[i] = 100;
        }
    }
}
```

---

## 归一化公式

### 通用公式

```
normalized_value = 100 + (raw_value - min_value) * 9900 / (max_value - min_value)
```

**参数**:
- `raw_value`: 原始值
- `min_value`: 所有节点中的最小值
- `max_value`: 所有节点中的最大值
- `normalized_value`: 归一化后的值，范围 [100, 10000]

### 特殊情况

**所有节点值相同**:
```cpp
if (max_value == min_value) {
    // 所有节点权重设为 100
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        weight[i] = 100;
    }
}
```

---

## FTS 计算公式

### 修改后

```
fts_value = 2 * ip_weight +
            2 * credit_weight +
            2 * pos_weight +
            2 * epoch_weight +
            2 * area_weight_smooth +
            2 * gap_weight
```

**所有权重范围**: [100, 10000]

**FTS 值范围**:
- 最小值: 2 * 100 * 6 = 1200
- 最大值: 2 * 10000 * 6 = 120000

---

## 对比：修改前 vs 修改后

### 修改前

| 因子 | 归一化方式 | 问题 |
|------|-----------|------|
| PoS | 基于 stoke 计算，范围不固定 | 主导归一化 |
| Credit | 依赖 `pos_diff` | 受 PoS 影响 |
| Area | 依赖 `pos_diff` | 受 PoS 影响 |
| IP | 依赖 `pos_diff` | 受 PoS 影响 |
| Gap | 依赖 `pos_diff` | 受 PoS 影响 |
| Epoch | 依赖 `pos_diff` | 受 PoS 影响 |

**问题**: 所有因子都受 PoS 权重影响，不独立

### 修改后

| 因子 | 归一化方式 | 优势 |
|------|-----------|------|
| PoS | 独立归一化到 [100, 10000] | ✅ 独立 |
| Credit | 独立归一化到 [100, 10000] | ✅ 独立 |
| Area | 独立归一化到 [100, 10000] | ✅ 独立 |
| IP | 独立归一化到 [100, 10000] | ✅ 独立 |
| Gap | 独立归一化到 [100, 10000] | ✅ 独立 |
| Epoch | 独立归一化到 [100, 10000] | ✅ 独立 |

**优势**: 所有因子独立，公平竞争

---

## 示例计算

### 场景：3 个节点

#### 原始数据

| 节点 | stoke | credit | tx_count | consensus_gap | area_weight |
|------|-------|--------|----------|---------------|-------------|
| A | 800000000 | 100 | 50 | 10 | 500 |
| B | 1600000000 | 200 | 100 | 20 | 1000 |
| C | 2400000000 | 300 | 150 | 30 | 1500 |

#### 归一化后（修改后）

**PoS 权重**:
```
min_pos = 100 (计算后的最小值)
max_pos = 140 (计算后的最大值)

Node A: pos_weight = 100 + (100 - 100) * 9900 / (140 - 100) = 100
Node B: pos_weight = 100 + (120 - 100) * 9900 / (140 - 100) = 5050
Node C: pos_weight = 100 + (140 - 100) * 9900 / (140 - 100) = 10000
```

**Credit 权重**:
```
min_credit = 100
max_credit = 300

Node A: credit_weight = 100 + (100 - 100) * 9900 / (300 - 100) = 100
Node B: credit_weight = 100 + (200 - 100) * 9900 / (300 - 100) = 5050
Node C: credit_weight = 100 + (300 - 100) * 9900 / (300 - 100) = 10000
```

**Epoch 权重**:
```
min_epoch = 50
max_epoch = 150

Node A: epoch_weight = 100 + (50 - 50) * 9900 / (150 - 50) = 100
Node B: epoch_weight = 100 + (100 - 50) * 9900 / (150 - 50) = 5050
Node C: epoch_weight = 100 + (150 - 50) * 9900 / (150 - 50) = 10000
```

**所有因子都独立归一化到 [100, 10000]！**

---

## 修改优势

### 1. 独立性

✅ **每个因子独立归一化**
- 不受其他因子影响
- 公平竞争

### 2. 一致性

✅ **所有因子范围一致**
- 都在 [100, 10000] 范围内
- 易于理解和调试

### 3. 可预测性

✅ **归一化结果可预测**
- 最小值总是 100
- 最大值总是 10000
- 中间值线性分布

### 4. 公平性

✅ **所有因子权重相等**
- 每个因子都乘以 2
- 不会因为归一化范围不同而影响权重

---

## 验证

### 编译验证
```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 日志验证

**期望输出**:
```
fts value final: 5050,5050,5050,5050,5050,5050,60600 --- ...
                 ip   cr   pos  ep   area gap  fts
                 
所有权重都在 [100, 10000] 范围内
```

---

## 总结

### 修改内容

✅ **独立归一化**: 每个因子独立归一化到 [100, 10000]  
✅ **移除依赖**: 不再依赖 PoS 权重作为归一化标准  
✅ **统一范围**: 所有因子范围一致  
✅ **公平竞争**: 所有因子权重相等

### 修改优势

1. ✅ **独立性**: 因子之间不相互影响
2. ✅ **一致性**: 所有因子范围一致
3. ✅ **可预测性**: 归一化结果可预测
4. ✅ **公平性**: 所有因子权重相等

**归一化独立计算完成！** ✅
