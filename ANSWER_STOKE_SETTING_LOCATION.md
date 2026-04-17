# 回答：elect_statistic_.join_elect_nodes(i).stoke() 在哪儿设置的？

## 直接答案

**位置**: `src/pools/shard_statistic.cc` 文件的 `addNewNode2JoinStatics()` 函数中（第 976 行）

**代码**:
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
        
        // ⭐ 关键：从 join_elect_stoke_map 中获取 stoke
        auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
        auto stoke = stoke_iter->second;  // ← 获取实际的 stoke 值
        
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

---

## 完整数据流

### 1. 质押时设置 join_info.stoke

**文件**: `src/consensus/zbft/join_elect_tx_item.cc:313`

```cpp
join_info.set_stoke(total_staked);  // 质押金额设置为 stoke
```

### 2. 区块中保存 join_info

**文件**: `src/consensus/zbft/join_elect_tx_item.cc:316`

```cpp
auto* block_join_info = view_block.mutable_block_info()->add_joins();
*block_join_info = join_info;  // 保存到区块
```

### 3. 统计收集 join_info.stoke

**文件**: `src/pools/shard_statistic.cc:330`

```cpp
auto& elect_stoke_map = join_elect_stoke_map[elect_height];
elect_stoke_map[join_addr] = join_info.stoke();  // 收集到 map
```

### 4. 设置 elect_statistic.join_elect_nodes[i].stoke ⭐

**文件**: `src/pools/shard_statistic.cc:976`

```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // 从 map 获取
join_elect_node->set_stoke(stoke);  // 设置到 elect_statistic
```

### 5. 使用 elect_statistic.join_elect_nodes[i].stoke()

**文件**: `src/consensus/zbft/elect_tx_item.cc:578`

```cpp
node_info->stoke = elect_statistic_.join_elect_nodes(i).stoke();  // 使用
```

---

## 数据流图

```
质押操作
    ↓
join_info.stoke = total_staked (join_elect_tx_item.cc:313)
    ↓
block.joins[i] = join_info (join_elect_tx_item.cc:316)
    ↓
join_elect_stoke_map[addr] = join_info.stoke() (shard_statistic.cc:330)
    ↓
elect_statistic.join_elect_nodes[i].stoke = stoke (shard_statistic.cc:976) ⭐
    ↓
node_info->stoke = elect_statistic_.join_elect_nodes(i).stoke() (elect_tx_item.cc:578)
    ↓
FTS 计算使用 stoke
```

---

## 关键修复

### 之前的 Bug

**位置**: `src/pools/shard_statistic.cc:976`

```cpp
auto stoke = 0;  // BUG: 硬编码为 0
join_elect_node->set_stoke(stoke);
```

### 修复后

```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // 从 map 获取实际值
join_elect_node->set_stoke(stoke);
```

---

## 验证方法

### 查看日志

```bash
tail -f logs/seth.log | grep "add new elect node"
```

**期望输出**:
```
add new elect node: XXX, stoke: 800000000, shard: YYY
```

如果看到 `stoke: 0`，说明 bug 未修复。  
如果看到 `stoke: 800000000`（或其他非零值），说明修复成功。

---

## 总结

**问题**: `elect_statistic_.join_elect_nodes(i).stoke()` 在哪儿设置的？

**答案**: 在 `src/pools/shard_statistic.cc` 文件的 `addNewNode2JoinStatics()` 函数中（第 976 行），通过以下代码设置：

```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;
join_elect_node->set_stoke(stoke);
```

**数据来源**: 从 `join_elect_stoke_map` 中获取，该 map 在处理区块的 `joins` 列表时填充，而 `joins` 中的 `stoke` 值来自质押操作时设置的 `join_info.stoke = total_staked`。

**验证**: 质押的 PoS 权重已正确集成到 FTS 选举算法中 ✅

---

## 相关文档

- `STAKING_STOKE_DATA_FLOW_ANSWER.md` - 完整数据流追踪
- `STAKING_STOKE_FLOW_DIAGRAM.md` - 可视化流程图
- `STAKING_DATA_FLOW_COMPLETE.md` - 数据流完整文档
- `FTS_POS_VERIFICATION.md` - FTS PoS 集成验证

**回答完成！** ✅
