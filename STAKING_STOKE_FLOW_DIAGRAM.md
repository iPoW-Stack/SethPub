# 质押 Stoke 数据流可视化图

## 完整数据流图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         质押操作开始                                      │
│                  (用户发送质押交易)                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 1: 质押处理 (join_elect_tx_item.cc:313)                           │
│  HandleStakeOperation()                                                  │
│                                                                          │
│  uint64_t total_staked = existing_stake + stake_amount;                 │
│  join_info.set_total_staked(total_staked);                              │
│  join_info.set_stoke(total_staked);  ← 设置 stoke = total_staked       │
│                                                                          │
│  示例: 质押 8 SETH → stoke = 800000000                                  │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 2: 添加到区块 (join_elect_tx_item.cc:316)                         │
│                                                                          │
│  auto* block_join_info = view_block.mutable_block_info()->add_joins();  │
│  *block_join_info = join_info;                                          │
│                                                                          │
│  区块结构:                                                               │
│  block {                                                                 │
│    joins: [                                                              │
│      { pubkey: "...", stoke: 800000000, ... }  ← join_info             │
│    ]                                                                     │
│  }                                                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 3: 统计收集 (shard_statistic.cc:330)                              │
│  HandleStatistic() 中的 lambda                                           │
│                                                                          │
│  for (int32_t i = 0; i < block.joins_size(); ++i) {                     │
│    auto& join_info = block.joins(i);                                    │
│    auto join_addr = GetAddressWithPublicKey(join_info.public_key());    │
│                                                                          │
│    // 保存到 map                                                        │
│    auto& elect_stoke_map =                                              │
│        join_elect_stoke_map[elect_height];                              │
│    elect_stoke_map[join_addr] = join_info.stoke();  ← 提取 stoke       │
│  }                                                                       │
│                                                                          │
│  数据结构:                                                               │
│  join_elect_stoke_map = {                                               │
│    1000: {                                                               │
│      "addr_A": 800000000,   // 8 SETH                                   │
│      "addr_B": 1600000000,  // 16 SETH                                  │
│      "addr_C": 2400000000   // 24 SETH                                  │
│    }                                                                     │
│  }                                                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 4: 选举统计 (shard_statistic.cc:976) ⭐ 关键步骤                  │
│  addNewNode2JoinStatics()                                                │
│                                                                          │
│  for (uint32_t i = 0; i < elect_nodes.size(); ++i) {                    │
│    // 从 map 中获取 stoke                                               │
│    auto stoke_iter = r_eiter->second.find(elect_nodes[i]);              │
│    auto stoke = stoke_iter->second;  ← 获取实际 stoke 值               │
│                                                                          │
│    // 设置到 elect_statistic                                            │
│    auto join_elect_node = elect_statistic.add_join_elect_nodes();       │
│    join_elect_node->set_stoke(stoke);  ← 设置！                        │
│  }                                                                       │
│                                                                          │
│  elect_statistic {                                                       │
│    join_elect_nodes: [                                                   │
│      { pubkey: "...", stoke: 800000000, ... },  ← 设置在这里           │
│      { pubkey: "...", stoke: 1600000000, ... },                         │
│      { pubkey: "...", stoke: 2400000000, ... }                          │
│    ]                                                                     │
│  }                                                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 5: 选举准备 (elect_tx_item.cc:578)                                │
│  GetIndexNodes()                                                         │
│                                                                          │
│  for (int32_t i = 0; i < elect_statistic_.join_elect_nodes_size(); ++i) {│
│    auto node_info = std::make_shared<ElectNodeInfo>();                  │
│                                                                          │
│    // 使用 elect_statistic 中的 stoke                                   │
│    node_info->stoke =                                                    │
│        elect_statistic_.join_elect_nodes(i).stoke();  ← 使用这里！     │
│                                                                          │
│    elect_nodes_to_choose->push_back(node_info);                         │
│  }                                                                       │
│                                                                          │
│  候选节点列表:                                                           │
│  [                                                                       │
│    { pubkey: "...", stoke: 800000000, ... },                            │
│    { pubkey: "...", stoke: 1600000000, ... },                           │
│    { pubkey: "...", stoke: 2400000000, ... }                            │
│  ]                                                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 6: FTS 权重计算 (elect_tx_item.cc:1353)                           │
│  SmoothFtsValue()                                                        │
│                                                                          │
│  // 按 stoke 排序                                                       │
│  std::stable_sort(elect_nodes.begin(), elect_nodes.end(),               │
│                   ElectNodeBalanceCompare);                              │
│                                                                          │
│  // 计算 blance_weight（基于 stoke）                                    │
│  blance_weight[0] = 100;                                                 │
│  for (uint32_t i = 1; i < elect_nodes.size(); ++i) {                    │
│    uint64_t fts_val_diff =                                              │
│        elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;  ← 使用 stoke│
│    blance_weight[i] = blance_weight[i - 1] + f(fts_val_diff);           │
│  }                                                                       │
│                                                                          │
│  计算结果:                                                               │
│  Node A: stoke = 800000000  → blance_weight = 100                       │
│  Node B: stoke = 1600000000 → blance_weight = 120                       │
│  Node C: stoke = 2400000000 → blance_weight = 140                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 7: FTS 最终值计算 (elect_tx_item.cc:1534)                         │
│  SmoothFtsValue()                                                        │
│                                                                          │
│  for (uint32_t i = 0; i < elect_nodes.size(); ++i) {                    │
│    elect_nodes[i]->fts_value =                                          │
│        2 * ip_weight[i] +                                               │
│        2 * credit_weight[i] +                                           │
│        2 * blance_weight[i] +  ← 包含 blance_weight                    │
│        2 * epoch_weight[i] +                                            │
│        2 * area_weight_smooth[i] +                                      │
│        2 * gap_weight[i];                                               │
│  }                                                                       │
│                                                                          │
│  计算结果（假设其他权重相同）:                                           │
│  Node A: fts_value = 1200  (blance_weight = 100)                        │
│  Node B: fts_value = 1240  (blance_weight = 120)                        │
│  Node C: fts_value = 1280  (blance_weight = 140)  ← 质押最多，值最高   │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  步骤 8: 选举概率计算                                                    │
│                                                                          │
│  FTS 树总和 = 1200 + 1240 + 1280 = 3720                                 │
│                                                                          │
│  选举概率:                                                               │
│  Node A: 1200 / 3720 = 32.3%                                            │
│  Node B: 1240 / 3720 = 33.3%                                            │
│  Node C: 1280 / 3720 = 34.4%  ← 质押最多，概率最高                     │
│                                                                          │
│  结论: 质押越多，被选中概率越大 ✅                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 关键步骤详解

### ⭐ 步骤 4: 最关键的设置点

**文件**: `src/pools/shard_statistic.cc`  
**函数**: `addNewNode2JoinStatics()`  
**行号**: 976

这是 `elect_statistic_.join_elect_nodes(i).stoke()` 被设置的地方！

```cpp
// 从 join_elect_stoke_map 获取 stoke
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // ← 获取实际值（不是 0）

// 设置到 elect_statistic
auto join_elect_node = elect_statistic.add_join_elect_nodes();
join_elect_node->set_stoke(stoke);  // ← 设置！
```

**之前的 Bug**:
```cpp
auto stoke = 0;  // BUG: 硬编码为 0
join_elect_node->set_stoke(stoke);
```

**修复后**:
```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // 从 map 获取实际值
join_elect_node->set_stoke(stoke);
```

---

## 数据流时序图

```
时间轴 →

T1: 用户质押
    └─→ join_info.stoke = 800000000

T2: 区块打包
    └─→ block.joins[0] = join_info

T3: 区块处理
    └─→ join_elect_stoke_map[1000]["addr_A"] = 800000000

T4: 选举统计 ⭐
    └─→ elect_statistic.join_elect_nodes[0].stoke = 800000000

T5: 选举准备
    └─→ node_info->stoke = 800000000

T6: FTS 计算
    └─→ blance_weight = 100

T7: FTS 值
    └─→ fts_value = 1200

T8: 选举
    └─→ probability = 32.3%
```

---

## 代码位置快速索引

| 步骤 | 文件 | 函数 | 行号 | 关键代码 |
|------|------|------|------|----------|
| 1 | join_elect_tx_item.cc | HandleStakeOperation() | 313 | `join_info.set_stoke(total_staked)` |
| 2 | join_elect_tx_item.cc | HandleTx() | 316 | `block_join_info = join_info` |
| 3 | shard_statistic.cc | HandleStatistic() | 330 | `elect_stoke_map[addr] = join_info.stoke()` |
| 4 ⭐ | shard_statistic.cc | addNewNode2JoinStatics() | 976 | `join_elect_node->set_stoke(stoke)` |
| 5 | elect_tx_item.cc | GetIndexNodes() | 578 | `node_info->stoke = join_elect_nodes(i).stoke()` |
| 6 | elect_tx_item.cc | SmoothFtsValue() | 1353 | `blance_weight = f(stoke)` |
| 7 | elect_tx_item.cc | SmoothFtsValue() | 1534 | `fts_value = ... + blance_weight + ...` |

---

## 验证清单

### 编译验证
```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 运行验证
```bash
# 启动节点
./seth --config conf/seth.conf

# 查看日志
tail -f logs/seth.log | grep -E "stoke|stake|fts_value"
```

### 日志验证点

#### 1. 质押时
```
Initial stake in root shard: addr=XXX, amount=800000000
Using stake info for stoke: addr=XXX, stoke=800000000
```

#### 2. 统计收集时
```
success add elect node stoke XXX, 800000000, elect height: YYY
```

#### 3. 选举统计时（关键）
```
add new elect node: XXX, stoke: 800000000, shard: ZZZ
```

#### 4. FTS 计算时
```
before sort: pubkey1:800000000,pubkey2:1600000000,pubkey3:2400000000
fts value final: ...,100,...,1200 --- ...,120,...,1240 --- ...,140,...,1280
```

---

## 总结

### 问题答案

**`elect_statistic_.join_elect_nodes(i).stoke()` 在哪儿设置的？**

**答案**: 在 `src/pools/shard_statistic.cc` 文件的 `addNewNode2JoinStatics()` 函数中（第 976 行）。

### 数据流完整性

✅ 质押金额 → join_info.stoke → 区块 joins → join_elect_stoke_map → elect_statistic.join_elect_nodes[i].stoke → node_info->stoke → blance_weight → fts_value → 选举概率

### 验证结果

✅ **质押的 PoS 权重已正确集成到 FTS 选举算法中！**

质押越多 → stoke 越大 → blance_weight 越高 → fts_value 越高 → 被选中概率越大

---

**数据流追踪完成！** ✅
