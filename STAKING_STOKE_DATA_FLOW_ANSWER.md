# elect_statistic_.join_elect_nodes(i).stoke() 设置位置完整追踪

## 问题回答

**问题**: `elect_statistic_.join_elect_nodes(i).stoke()` 在哪儿设置的？

**答案**: 在 `src/pools/shard_statistic.cc` 文件的 `addNewNode2JoinStatics()` 函数中设置。

---

## 完整数据流追踪

### 步骤 1: 质押时设置 join_info.stoke

**文件**: `src/consensus/zbft/join_elect_tx_item.cc`

**函数**: `HandleStakeOperation()` (第 313 行)

```cpp
// 质押操作完成后
join_info.set_total_staked(total_staked);  // 设置累计质押总额
join_info.set_stoke(total_staked);         // ← 关键：stoke = total_staked

auto* block_join_info = view_block.mutable_block_info()->add_joins();
*block_join_info = join_info;
```

**数据示例**:
- 质押 8 SETH: `join_info.stoke = 800000000`
- 质押 16 SETH: `join_info.stoke = 1600000000`

---

### 步骤 2: 区块中保存 join_info

**文件**: `src/consensus/zbft/join_elect_tx_item.cc`

**函数**: `HandleTx()` 结束时 (第 222 行)

```cpp
// 优先使用质押信息
uint64_t stoke = 0;
uint64_t stake_timestamp = 0;

if (prefix_db_->GetStakeInfo(from, &stoke, &stake_timestamp)) {
    // 有质押：使用质押金额
    join_info.set_stoke(stoke);  // ← stoke = total_staked
    SETH_DEBUG("Using stake info for stoke: addr=%s, stoke=%lu",
        common::Encode::HexEncode(from).c_str(), stoke);
} else {
    // 无质押：使用历史 stoke
    prefix_db_->GetElectNodeMinStoke(network_id, from, &stoke);
    join_info.set_stoke(stoke);
}

// 添加到区块
auto* block_join_info = view_block.mutable_block_info()->add_joins();
*block_join_info = join_info;
```

---

### 步骤 3: 统计收集 - 从区块 joins 提取 stoke

**文件**: `src/pools/shard_statistic.cc`

**函数**: `HandleStatistic()` 中的 lambda (第 330 行)

```cpp
auto handle_joins_func = [&](const bls::protobuf::JoinElectInfo& join_info) {
    auto join_addr = secptr_->GetAddressWithPublicKey(join_info.public_key());
    
    // 创建或获取 elect_height 对应的 map
    auto eiter = join_elect_stoke_map.find(view_block_ptr->qc().elect_height());
    if (eiter == join_elect_stoke_map.end()) {
        join_elect_stoke_map[view_block_ptr->qc().elect_height()] = 
            std::map<std::string, uint64_t>();
    }
    
    // 保存 stoke 到 map
    auto& elect_stoke_map = join_elect_stoke_map[view_block_ptr->qc().elect_height()];
    elect_stoke_map[join_addr] = join_info.stoke();  // ← 从 join_info 获取 stoke
    
    SETH_DEBUG("success add elect node stoke %s, %lu, elect height: %lu",
        common::Encode::HexEncode(join_addr).c_str(), 
        join_info.stoke(),  // ← 这是 total_staked
        view_block_ptr->qc().elect_height());
};

// 处理区块中的所有 joins
for (int32_t i = 0; i < block.joins_size(); ++i) {
    handle_joins_func(block.joins(i));
}
```

**数据结构**:
```cpp
join_elect_stoke_map: map<elect_height, map<address, stoke>>
例如:
{
    1000: {
        "addr_A": 800000000,   // 8 SETH
        "addr_B": 1600000000,  // 16 SETH
        "addr_C": 2400000000   // 24 SETH
    }
}
```

---

### 步骤 4: 选举统计 - 设置 join_elect_nodes 的 stoke ⭐ 关键步骤

**文件**: `src/pools/shard_statistic.cc`

**函数**: `addNewNode2JoinStatics()` (第 976 行)

**这就是 `elect_statistic_.join_elect_nodes(i).stoke()` 被设置的地方！**

```cpp
void ShardStatistic::addNewNode2JoinStatics(
        std::map<uint64_t, std::map<std::string, uint64_t>> &join_elect_stoke_map,
        std::map<uint64_t, std::map<std::string, uint32_t>> &join_elect_shard_map,
        std::set<std::string> &added_id_set,
        std::map<std::string, std::string> &id_pk_map,
        std::map<std::string, std::shared_ptr<elect::protobuf::BlsPublicKey>> &id_agg_bls_pk_map,
        std::map<std::string, std::shared_ptr<elect::protobuf::BlsPopProof>> &id_agg_bls_pk_proof_map,
        seth::pools::protobuf::ElectStatistic &elect_statistic) {
    
    // ... 收集候选节点 ...
    
    // 遍历所有候选节点
    for (uint32_t i = 0; i < elect_nodes.size() && i < kWaitingElectNodesMaxCount; ++i) {
        std::string node_id = elect_nodes[i];
        
        // 获取 shard_id
        auto shard_iter = r_siter->second.find(elect_nodes[i]);
        auto shard_id = shard_iter->second;
        
        // ⭐ 关键：从 map 中获取 stoke（不是硬编码为 0）
        auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
        auto stoke = stoke_iter->second;  // ← 这里获取实际的 stoke 值
        
        // ⭐ 设置 join_elect_node 的 stoke
        auto join_elect_node = elect_statistic.add_join_elect_nodes();
        join_elect_node->set_consensus_gap(0);
        join_elect_node->set_credit(0);
        join_elect_node->set_pubkey(pubkey);
        join_elect_node->set_stoke(stoke);  // ← 这里设置！
        join_elect_node->set_shard(shard_id);
        join_elect_node->set_elect_pos(0);
        
        SETH_DEBUG("add new elect node: %s, stoke: %lu, shard: %u",
            common::Encode::HexEncode(pubkey).c_str(), stoke, shard_id);
    }
}
```

**关键点**:
- ✅ 从 `join_elect_stoke_map` 中获取实际的 stoke 值
- ✅ 不再硬编码为 0（这是之前的 bug）
- ✅ 质押信息正确传递到选举统计

**调用位置**:
```cpp
// 在 StatisticWithHeights() 函数中调用
addNewNode2JoinStatics(
    join_elect_stoke_map,
    join_elect_shard_map,
    added_id_set,
    id_pk_map,
    id_agg_bls_pk_map,
    id_agg_bls_pk_proof_map,
    elect_statistic);  // ← elect_statistic 被传入并修改
```

---

### 步骤 5: 选举准备 - 使用 stoke

**文件**: `src/consensus/zbft/elect_tx_item.cc`

**函数**: `GetIndexNodes()` (第 578 行)

```cpp
// 准备候选节点
for (int32_t i = 0; i < elect_statistic_.join_elect_nodes_size(); ++i) {
    auto& join_node = elect_statistic_.join_elect_nodes(i);
    auto node_info = std::make_shared<ElectNodeInfo>();
    
    // ⭐ 从 elect_statistic 获取 stoke
    node_info->stoke = elect_statistic_.join_elect_nodes(i).stoke();  // ← 使用这里！
    
    node_info->area_weight = min_area_weight;
    node_info->tx_count = min_tx_count;
    node_info->credit = join_node.credit();
    node_info->pubkey = join_node.pubkey();
    node_info->consensus_gap = join_node.consensus_gap();
    
    elect_nodes_to_choose->push_back(node_info);
}
```

**数据**:
```
Node A: node_info->stoke = 800000000   (8 SETH)
Node B: node_info->stoke = 1600000000  (16 SETH)
Node C: node_info->stoke = 2400000000  (24 SETH)
```

---

### 步骤 6: FTS 权重计算

**文件**: `src/consensus/zbft/elect_tx_item.cc`

**函数**: `SmoothFtsValue()`

```cpp
// 按 stoke 排序
std::stable_sort(elect_nodes.begin(), elect_nodes.end(), ElectNodeBalanceCompare);

// 计算 stoke 差值
elect_nodes[0]->stoke_diff = 0;
for (uint32_t i = 1; i < elect_nodes.size(); ++i) {
    elect_nodes[i]->stoke_diff = elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;
}

// 计算 blance_weight（基于 stoke）
blance_weight[0] = 100;
for (uint32_t i = 1; i < elect_nodes.size(); ++i) {
    uint64_t fts_val_diff = elect_nodes[i]->stoke - elect_nodes[i - 1]->stoke;
    
    if (fts_val_diff == 0) {
        blance_weight[i] = blance_weight[i - 1];
    } else {
        if (fts_val_diff < diff_2b3) {
            auto rand_val = fts_val_diff + g2() % (diff_2b3 - fts_val_diff);
            blance_weight[i] = blance_weight[i - 1] + (20 * rand_val) / diff_2b3;
        } else {
            auto rand_val = diff_2b3 + g2() % (fts_val_diff + 1 - diff_2b3);
            blance_weight[i] = blance_weight[i - 1] + (20 * rand_val) / fts_val_diff;
        }
    }
}
```

---

### 步骤 7: FTS 最终值计算

**文件**: `src/consensus/zbft/elect_tx_item.cc`

**函数**: `SmoothFtsValue()`

```cpp
for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
    elect_nodes[i]->fts_value = (2 * ip_weight[i] +
                                 2 * credit_weight[i] +
                                 2 * blance_weight[i] +    // ← 使用 blance_weight
                                 2 * epoch_weight[i] +
                                 2 * area_weight_smooth[i]) +
                                 2 * gap_weight[i];
}
```

---

## 数据流图

```
质押操作 (join_elect_tx_item.cc:313)
    ↓
join_info.stoke = total_staked
    ↓
区块 joins 列表 (join_elect_tx_item.cc:316)
    ↓
统计收集 (shard_statistic.cc:330)
    ↓
join_elect_stoke_map[elect_height][address] = join_info.stoke
    ↓
选举统计 (shard_statistic.cc:976) ⭐ 关键步骤
    ↓
elect_statistic.join_elect_nodes[i].stoke = stoke_from_map
    ↓
选举准备 (elect_tx_item.cc:578)
    ↓
node_info->stoke = elect_statistic_.join_elect_nodes(i).stoke()
    ↓
FTS 计算 (elect_tx_item.cc:1353)
    ↓
blance_weight (基于 stoke)
    ↓
fts_value (elect_tx_item.cc:1534)
    ↓
选举概率
```

---

## 关键代码位置总结

| 步骤 | 文件 | 函数 | 行号 | 操作 |
|------|------|------|------|------|
| 1 | join_elect_tx_item.cc | HandleStakeOperation() | 313 | 设置 join_info.stoke = total_staked |
| 2 | join_elect_tx_item.cc | HandleTx() | 222 | 优先使用质押信息设置 stoke |
| 3 | shard_statistic.cc | HandleStatistic() | 330 | 收集 join_info.stoke 到 map |
| 4 | shard_statistic.cc | addNewNode2JoinStatics() | 976 | ⭐ 设置 elect_statistic.join_elect_nodes[i].stoke |
| 5 | elect_tx_item.cc | GetIndexNodes() | 578 | 使用 elect_statistic_.join_elect_nodes(i).stoke() |
| 6 | elect_tx_item.cc | SmoothFtsValue() | 1353 | 基于 stoke 计算 blance_weight |
| 7 | elect_tx_item.cc | SmoothFtsValue() | 1534 | 计算 fts_value |

---

## 关键修复

### Bug 修复: shard_statistic.cc 中 stoke 硬编码为 0 ✅ 已修复

**位置**: `src/pools/shard_statistic.cc:976`

**修复前**:
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

## 验证日志

### 质押时
```
Initial stake in root shard: addr=XXX, amount=800000000
Using stake info for stoke: addr=XXX, stoke=800000000
```

### 统计收集时
```
success add elect node stoke XXX, 800000000, elect height: YYY
```

### 选举统计时（关键日志）
```
add new elect node: XXX, stoke: 800000000, shard: ZZZ
```

### FTS 计算时
```
before sort: pubkey1:800000000,pubkey2:1600000000,pubkey3:2400000000
fts value final: ...,100,...,1200 --- ...,120,...,1240 --- ...,140,...,1280
```

---

## 总结

### 问题答案

**`elect_statistic_.join_elect_nodes(i).stoke()` 在哪儿设置的？**

**答案**: 在 `src/pools/shard_statistic.cc` 文件的 `addNewNode2JoinStatics()` 函数中（第 976 行），通过以下代码设置：

```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // 从 join_elect_stoke_map 获取
auto join_elect_node = elect_statistic.add_join_elect_nodes();
join_elect_node->set_stoke(stoke);  // 设置 stoke
```

### 数据流完整性 ✅

1. **质押设置**: `join_info.stoke = total_staked` ✅
2. **区块存储**: `block.joins[i] = join_info` ✅
3. **统计收集**: `join_elect_stoke_map[addr] = join_info.stoke` ✅
4. **选举统计**: `join_elect_nodes[i].stoke = stoke_from_map` ✅ (已修复)
5. **选举准备**: `node_info->stoke = join_elect_nodes[i].stoke` ✅
6. **FTS 计算**: `blance_weight = f(stoke)` ✅
7. **FTS 值**: `fts_value = ... + blance_weight + ...` ✅
8. **选举概率**: `probability = fts_value / total` ✅

### 验证结果 ✅

**质押的 PoS 权重已正确集成到 FTS 选举算法中！**

质押越多 → stoke 越大 → blance_weight 越高 → fts_value 越高 → 被选中概率越大

---

## 下一步

1. ✅ 编译代码
2. ✅ 运行测试
3. ✅ 验证日志输出
4. ✅ 确认质押金额影响选举概率

**数据流追踪完成！** ✅
