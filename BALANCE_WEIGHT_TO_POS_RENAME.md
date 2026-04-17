# balance_weight 重命名为 pos_weight

## 修改说明

将 `elect_tx_item.cc` 中的 `blance_weight` 重命名为 `pos_weight`，使代码更清晰地表达这是 PoS（Proof of Stake）权重。

**注意**: 原代码中有拼写错误 `blance_weight` 而不是 `balance_weight`。

---

## 修改内容

### 文件: `src/consensus/zbft/elect_tx_item.cc`

### 函数: `SmoothFtsValue()`

#### 变量重命名

| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `blance_weight` | `pos_weight` | PoS 权重向量 |
| `blance_diff` | `pos_diff` | PoS 权重差值 |

#### 修改详情

**1. 变量声明**
```cpp
// 修改前
std::vector<int32_t> blance_weight;
int32_t blance_diff = 0;

// 修改后
std::vector<int32_t> pos_weight;
int32_t pos_diff = 0;
```

**2. PoS 权重计算**
```cpp
// 修改前
blance_weight.resize(elect_nodes.size(), 0);
blance_weight[0] = 100;
for (uint32_t i = 1; i < elect_nodes.size(); ++i) {
    uint64_t fts_val_diff = elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;
    if (fts_val_diff == 0) {
        blance_weight[i] = blance_weight[i - 1];
    } else {
        // ... 计算逻辑 ...
        blance_weight[i] = blance_weight[i - 1] + ...;
    }
}

// 修改后
pos_weight.resize(elect_nodes.size(), 0);
pos_weight[0] = 100;
for (uint32_t i = 1; i < elect_nodes.size(); ++i) {
    uint64_t fts_val_diff = elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;
    if (fts_val_diff == 0) {
        pos_weight[i] = pos_weight[i - 1];
    } else {
        // ... 计算逻辑 ...
        pos_weight[i] = pos_weight[i - 1] + ...;
    }
}
```

**3. 权重差值计算**
```cpp
// 修改前
blance_diff = max_balance - min_balance;
if (max_balance - min_balance < 1000) {
    // ... 调整逻辑 ...
    blance_diff = max_balance - min_balance;
}

// 修改后
pos_diff = max_balance - min_balance;
if (max_balance - min_balance < 1000) {
    // ... 调整逻辑 ...
    pos_diff = max_balance - min_balance;
}
```

**4. 其他权重归一化**

所有使用 `blance_diff` 的地方都改为 `pos_diff`：

```cpp
// credit_weight 归一化
int32_t credit_index = pos_diff / credit_diff;  // 原: blance_diff

// area_weight_smooth 归一化
int32_t area_weight_index = pos_diff / area_weight_diff;  // 原: blance_diff

// ip_weight 归一化
int32_t weight_index = pos_diff / weight_diff;  // 原: blance_diff

// gap_weight 归一化
int32_t weight_index = pos_diff / weight_diff;  // 原: blance_diff

// epoch_weight 归一化
int32_t weight_index = pos_diff / weight_diff;  // 原: blance_diff
```

**5. FTS 值计算**
```cpp
// 修改前
elect_nodes[i]->fts_value = (2 * ip_weight[i] +
                             2 * credit_weight[i] +
                             2 * blance_weight[i] +
                             2 * epoch_weight[i] +
                             2 * area_weight_smooth[i]) +
                             2 * gap_weight[i];

// 修改后
elect_nodes[i]->fts_value = (2 * ip_weight[i] +
                             2 * credit_weight[i] +
                             2 * pos_weight[i] +
                             2 * epoch_weight[i] +
                             2 * area_weight_smooth[i]) +
                             2 * gap_weight[i];
```

**6. 日志输出**
```cpp
// 修改前
fts_val_str += std::to_string(ip_weight[i]) + "," +
               std::to_string(credit_weight[i]) + "," +
               std::to_string(blance_weight[i]) + "," +
               std::to_string(epoch_weight[i]) + "," +
               std::to_string(area_weight_smooth[i]) + "," +
               std::to_string(gap_weight[i]) + "," +
               std::to_string(elect_nodes[i]->fts_value) + " --- ";

// 修改后
fts_val_str += std::to_string(ip_weight[i]) + "," +
               std::to_string(credit_weight[i]) + "," +
               std::to_string(pos_weight[i]) + "," +
               std::to_string(epoch_weight[i]) + "," +
               std::to_string(area_weight_smooth[i]) + "," +
               std::to_string(gap_weight[i]) + "," +
               std::to_string(elect_nodes[i]->fts_value) + " --- ";
```

---

## 修改原因

### 1. 语义清晰

**原名称问题**:
- `blance_weight` 有拼写错误（应该是 `balance`）
- `balance` 含义模糊，不清楚是什么类型的平衡

**新名称优势**:
- `pos_weight` 明确表示这是 PoS（Proof of Stake）权重
- 与质押（staking）功能直接关联
- 代码可读性更强

### 2. 一致性

**与其他权重命名一致**:
- `ip_weight` - IP 权重
- `credit_weight` - 信用权重
- `epoch_weight` - Epoch 权重
- `gap_weight` - Gap 权重
- `area_weight_smooth` - 区域权重
- `pos_weight` - PoS 权重 ✅

### 3. 可维护性

**更容易理解代码逻辑**:
```cpp
// 清晰表达：基于质押金额（stoke）计算 PoS 权重
uint64_t fts_val_diff = elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;
pos_weight[i] = pos_weight[i - 1] + ...;
```

---

## FTS 计算公式

### 修改后的公式

```
fts_value = 2 * ip_weight +
            2 * credit_weight +
            2 * pos_weight +        ← PoS 权重（基于质押）
            2 * epoch_weight +
            2 * area_weight_smooth +
            2 * gap_weight
```

### 各权重说明

| 权重 | 基于 | 说明 |
|------|------|------|
| `ip_weight` | 地理分布 | IP 地址分布权重 |
| `credit_weight` | 信用 | 节点信用权重 |
| `pos_weight` | 质押金额（stoke） | ⭐ PoS 权重（质押越多，权重越高） |
| `epoch_weight` | 交易数量 | Epoch 交易权重 |
| `area_weight_smooth` | 地理区域 | 区域分布权重 |
| `gap_weight` | 共识间隔 | 共识间隔权重 |

---

## 日志变化

### 修改前
```
fts value final: 100,100,100,100,100,100,1200 --- 100,100,120,100,100,100,1240 --- ...
                 ip  cr  bal ep  area gap fts
```

### 修改后
```
fts value final: 100,100,100,100,100,100,1200 --- 100,100,120,100,100,100,1240 --- ...
                 ip  cr  pos ep  area gap fts
```

**说明**: 第三个值现在明确表示 PoS 权重

---

## 影响范围

### 修改的代码行数

- 变量声明: 2 处
- 权重计算: ~15 处
- 权重归一化: 5 处
- FTS 计算: 1 处
- 日志输出: 1 处

**总计**: 约 24 处修改

### 不影响的部分

- ✅ 计算逻辑完全不变
- ✅ 算法行为完全不变
- ✅ 只是变量名称改变
- ✅ 不需要修改其他文件

---

## 测试验证

### 编译验证
```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 功能验证

**验证点**:
1. ✅ 编译通过
2. ✅ FTS 计算结果与之前一致
3. ✅ 日志输出格式正确
4. ✅ 选举概率计算正确

**测试场景**:
```
1. 节点 A 质押 8 SETH
2. 节点 B 质押 16 SETH
3. 节点 C 质押 24 SETH
4. 运行选举
5. 验证 pos_weight: A < B < C
6. 验证 fts_value: A < B < C
7. 验证选举概率: A < B < C
```

---

## 代码对比

### 修改前
```cpp
std::vector<int32_t> blance_weight;  // 拼写错误 + 语义不清
int32_t blance_diff = 0;

blance_weight[i] = blance_weight[i - 1] + ...;
int32_t credit_index = blance_diff / credit_diff;

elect_nodes[i]->fts_value = ... + 2 * blance_weight[i] + ...;
```

### 修改后
```cpp
std::vector<int32_t> pos_weight;  // 清晰表达 PoS 权重
int32_t pos_diff = 0;

pos_weight[i] = pos_weight[i - 1] + ...;
int32_t credit_index = pos_diff / credit_diff;

elect_nodes[i]->fts_value = ... + 2 * pos_weight[i] + ...;
```

---

## 总结

### 修改内容

✅ 将 `blance_weight` 重命名为 `pos_weight`  
✅ 将 `blance_diff` 重命名为 `pos_diff`  
✅ 更新所有相关引用（约 24 处）

### 修改优势

1. ✅ **语义清晰**: 明确表示 PoS 权重
2. ✅ **修正拼写**: 修复 `blance` 拼写错误
3. ✅ **一致性**: 与其他权重命名风格一致
4. ✅ **可维护性**: 代码更易理解和维护

### 不影响

- ✅ 计算逻辑不变
- ✅ 算法行为不变
- ✅ 性能不变
- ✅ 其他文件不需要修改

**重命名完成！** ✅
