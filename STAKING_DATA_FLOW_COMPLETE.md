# 质押数据流完整追踪

## 数据流概览

```
质押操作 (join_elect_tx_item.cc)
    ↓
join_info.stoke = total_staked
    ↓
区块 joins 列表
    ↓
统计收集 (shard_statistic.cc)
    ↓
join_elect_stoke_map[elect_height][address] = join_info.stoke
    ↓
选举统计 (shard_statistic.cc)
    ↓
elect_statistic.join_elect_nodes[i].stoke = stoke_from_map
    ↓
选举计算 (elect_tx_item.cc)
    ↓
node_info->stoke = join_elect_nodes[i].stoke
    ↓
FTS 计算
    ↓
blance_weight (基于 stoke)
    ↓
fts_value
    ↓
选举概率
```

## 详细代码追踪

### 步骤 1: 质押时设置 stoke

**文件**: `src/consensus/zbft/join_elect_tx_item.cc`

**函数**: `HandleStakeOperation()`

```cpp
// 计算总质押
uint64_t total_staked = existing_stake + stake_amount;

// 设置 join_info
join_info.set_total_staked(total_staked);
join_info.set_stoke(total_staked);  // ← 关键：stoke = total_staked

// 添加到区块
auto* block_join_info = view_block.mutable_block_info()->add_joins();
*block_join_info = join_info;
```

**数据**:
- 质押 8 SETH: `join_info.stoke = 800000000`
- 质押 16 SETH: `join_info.stoke = 1600000000`

---

### 步骤 2: 普通 join_elect 也使用质押信息

**文件**: `src/consensus/zbft/join_elect_tx_item.cc`

**函数**: `HandleTx()` 结束时

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
    SETH_DEBUG("Using historical min stoke: addr=%s, stoke=%lu",
        common::Encode::HexEncode(from).c_str(), stoke);
}
```

**关键点**:
- ✅ 确保有质押的节点始终使用质押金额
- ✅ 即使是普通 join_elect，也会使用质押信息

---

### 步骤 3: 统计收集 - 从区块 joins 提取 stoke

**文件**: `src/pools/shard_statistic.cc`

**函数**: `HandleMessage()` 中的 lambda

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

### 步骤 4: 选举统计 - 设置 join_elect_nodes 的 stoke

**文件**: `src/pools/shard_statistic.cc`

**函数**: `addNewNode2JoinStatics()`

**修复前的 BUG**:
```cpp
auto stoke = 0;  // ← BUG: 硬编码为 0
auto join_elect_node = elect_statistic.add_join_elect_nodes();
join_elect_node->set_stoke(stoke);  // ← 总是设置为 0
```

**修复后**:
```cpp
auto shard_iter = r_siter->second.find(elect_nodes[i]);
auto shard_id = shard_iter->second;

// 从 map 中获取 stoke
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // ← 修复：使用 map 中的值

auto join_elect_node = elect_statistic.add_join_elect_nodes();
join_elect_node->set_consensus_gap(0);
join_elect_node->set_credit(0);
join_elect_node->set_pubkey(pubkey);
join_elect_node->set_stoke(stoke);  // ← 现在使用正确的 stoke 值
join_elect_node->set_shard(shard_id);

SETH_DEBUG("add new elect node: %s, stoke: %lu, shard: %u",
    common::Encode::HexEncode(pubkey).c_str(), stoke, shard_id);
```

**关键修复**:
- ✅ 从 `join_elect_stoke_map` 中获取实际的 stoke 值
- ✅ 不再硬编码为 0
- ✅ 质押信息正确传递到选举统计

---

### 步骤 5: 选举准备 - 使用 stoke

**文件**: `src/consensus/zbft/elect_tx_item.cc`

**函数**: `DoElect()`

```cpp
// 准备候选节点
for (int32_t i = 0; i < elect_statistic_.join_elect_nodes_size(); ++i) {
    auto& join_node = elect_statistic_.join_elect_nodes(i);
    auto node_info = std::make_shared<ElectNodeInfo>();
    
    // 从 elect_statistic 获取 stoke
    node_info->stoke = join_node.stoke();  // ← 这是从 map 中获取的 total_staked
    
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

**计算示例**:
```
输入:
Node A: stoke = 800000000
Node B: stoke = 1600000000
Node C: stoke = 2400000000

排序后:
Node A: stoke_diff = 0
Node B: stoke_diff = 800000000
Node C: stoke_diff = 800000000

blance_weight 计算:
Node A: blance_weight = 100
Node B: blance_weight = 100 + (20 * 800000000) / 800000000 = 120
Node C: blance_weight = 120 + (20 * 800000000) / 800000000 = 140
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

**计算示例**:
```
假设其他权重相同：
ip_weight = 100, credit_weight = 100, epoch_weight = 100,
area_weight = 100, gap_weight = 100

Node A: fts_value = 2*100 + 2*100 + 2*100 + 2*100 + 2*100 + 2*100 = 1200
Node B: fts_value = 2*100 + 2*100 + 2*120 + 2*100 + 2*100 + 2*100 = 1240
Node C: fts_value = 2*100 + 2*100 + 2*140 + 2*100 + 2*100 + 2*100 = 1280
```

---

### 步骤 8: 选举概率

**文件**: `src/consensus/zbft/elect_tx_item.cc`

**函数**: `DoElect()`

```cpp
// 构建 FTS 树
for (auto iter = elect_nodes.begin(); iter != elect_nodes.end(); ++iter) {
    fts_tree.AppendFtsNode((*iter)->fts_value, idx);
}

// 随机选择
for (uint32_t i = 0; i < member_count; ++i) {
    auto rand_num = common::Random::RandomUint64() % fts_tree.Sum();
    auto idx = fts_tree.GetFtsNode(rand_num);
    // 选中的节点
}
```

**选举概率**:
```
FTS 树总和 = 1200 + 1240 + 1280 = 3720

Node A 概率 = 1200 / 3720 = 32.3%
Node B 概率 = 1240 / 3720 = 33.3%
Node C 概率 = 1280 / 3720 = 34.4%  ← 质押最多，概率最高
```

## 关键修复

### Bug 1: shard_statistic.cc 中 stoke 硬编码为 0 ✅ 已修复

**位置**: `src/pools/shard_statistic.cc:976`

**修复前**:
```cpp
auto stoke = 0;  // BUG
join_elect_node->set_stoke(stoke);
```

**修复后**:
```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // 从 map 获取
join_elect_node->set_stoke(stoke);
```

### Bug 2: join_elect_tx_item.cc 未使用质押信息 ✅ 已修复

**位置**: `src/consensus/zbft/join_elect_tx_item.cc:222`

**修复前**:
```cpp
prefix_db_->GetElectNodeMinStoke(network_id, from, &stoke);
join_info.set_stoke(stoke);
```

**修复后**:
```cpp
if (prefix_db_->GetStakeInfo(from, &stoke, &stake_timestamp)) {
    join_info.set_stoke(stoke);  // 优先使用质押
} else {
    prefix_db_->GetElectNodeMinStoke(network_id, from, &stoke);
    join_info.set_stoke(stoke);  // 回退到历史
}
```

## 数据流验证

### 完整追踪示例

**场景**: Node A 质押 8 SETH

```
1. 质押操作
   join_elect_tx_item.cc:313
   join_info.set_stoke(800000000)
   
2. 添加到区块
   join_elect_tx_item.cc:316
   block_join_info = join_info
   
3. 统计收集
   shard_statistic.cc:330
   elect_stoke_map[addr_A] = 800000000
   
4. 选举统计
   shard_statistic.cc:978
   join_elect_node->set_stoke(800000000)
   
5. 选举准备
   elect_tx_item.cc:579
   node_info->stoke = 800000000
   
6. FTS 计算
   elect_tx_item.cc:1353
   blance_weight[i] = f(stoke)
   
7. FTS 值
   elect_tx_item.cc:1534
   fts_value = ... + 2*blance_weight + ...
   
8. 选举概率
   elect_tx_item.cc:1268
   probability = fts_value / total_fts
```

## 日志验证点

### 质押时
```
Initial stake in root shard: addr=XXX, amount=800000000
Using stake info for stoke: addr=XXX, stoke=800000000
```

### 统计收集时
```
success add elect node stoke XXX, 800000000, elect height: YYY
```

### 选举统计时
```
add new elect node: XXX, stoke: 800000000, shard: ZZZ
```

### FTS 计算时
```
before sort: pubkey1:800000000,pubkey2:1600000000,pubkey3:2400000000
fts value final: ...,100,...,1200 --- ...,120,...,1240 --- ...,140,...,1280
```

## 总结

### 数据流完整性 ✅

1. **质押设置**: `join_info.stoke = total_staked` ✅
2. **区块存储**: `block.joins[i] = join_info` ✅
3. **统计收集**: `join_elect_stoke_map[addr] = join_info.stoke` ✅
4. **选举统计**: `join_elect_nodes[i].stoke = stoke_from_map` ✅ (已修复)
5. **选举准备**: `node_info->stoke = join_elect_nodes[i].stoke` ✅
6. **FTS 计算**: `blance_weight = f(stoke)` ✅
7. **FTS 值**: `fts_value = ... + blance_weight + ...` ✅
8. **选举概率**: `probability = fts_value / total` ✅

### 关键修复 ✅

- ✅ 修复 `shard_statistic.cc` 中 stoke 硬编码为 0 的 bug
- ✅ 修复 `join_elect_tx_item.cc` 未使用质押信息的问题

### 验证结果 ✅

**质押的 PoS 权重已正确集成到 FTS 选举算法中！**

质押越多 → stoke 越大 → blance_weight 越高 → fts_value 越高 → 被选中概率越大
