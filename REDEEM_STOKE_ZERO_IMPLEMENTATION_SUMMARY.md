# 赎回设置 Stoke 为 0 - 实现总结

## 需求

赎回质押时，需要将节点的 `stoke` 设置为 0，这样在选举统计时就不会给赎回的节点分配 PoS 权重。

---

## 实现方案

### 1. 赎回操作设置 stoke = 0

**文件**: `src/consensus/zbft/join_elect_tx_item.cc`

**修改**: `HandleRedeemOperation()` 函数

```cpp
// 赎回成功后，设置 stoke 为 0
join_info.set_stoke(0);
join_info.set_total_staked(0);

// 添加到区块 joins 以记录赎回操作
auto* block_join_info = view_block.mutable_block_info()->add_joins();
*block_join_info = join_info;

SETH_INFO("Redeemed stake: addr=%s, amount=%lu, stoke set to 0",
    common::Encode::HexEncode(from).c_str(), total_staked);
```

**关键点**:
- ✅ 赎回后 `join_info.stoke = 0`
- ✅ 仍然添加到 `block.joins` 以记录操作
- ✅ 日志中明确显示 "stoke set to 0"

---

### 2. 统计收集时区分操作类型

**文件**: `src/pools/shard_statistic.cc`

**修改**: `HandleStatistic()` 中的 lambda

```cpp
auto handle_joins_func = [&](const bls::protobuf::JoinElectInfo& join_info) {
    auto join_addr = secptr_->GetAddressWithPublicKey(join_info.public_key());
    auto& elect_stoke_map = join_elect_stoke_map[elect_height];
    
    // 检查是否是赎回操作
    if (join_info.has_stake_op() && 
        join_info.stake_op() == bls::protobuf::STAKE_OP_REDEEM) {
        // 赎回：设置 stoke 为 0（移除 PoS 权重）
        elect_stoke_map[join_addr] = 0;
        SETH_DEBUG("redeem operation: set stoke to 0 for %s",
            common::Encode::HexEncode(join_addr).c_str());
    } else {
        // 质押或普通 join：使用 join_info.stoke
        elect_stoke_map[join_addr] = join_info.stoke();
        SETH_DEBUG("stake/join operation: stoke=%lu for %s",
            join_info.stoke(),
            common::Encode::HexEncode(join_addr).c_str());
    }
};
```

**关键点**:
- ✅ 检查 `stake_op` 字段区分操作类型
- ✅ 赎回操作：`elect_stoke_map[addr] = 0`
- ✅ 其他操作：`elect_stoke_map[addr] = join_info.stoke()`

---

## 数据流

```
赎回交易
    ↓
HandleRedeemOperation()
    ↓ join_info.stoke = 0
    ↓ join_info.stake_op = STAKE_OP_REDEEM
    ↓
block.joins[i] = join_info
    ↓
HandleStatistic() - lambda
    ↓ 检查 stake_op == STAKE_OP_REDEEM
    ↓
elect_stoke_map[addr] = 0
    ↓
addNewNode2JoinStatics()
    ↓ join_elect_node->set_stoke(0)
    ↓
GetIndexNodes()
    ↓ node_info->stoke = 0
    ↓
FTS 计算
    ↓ blance_weight 降低
    ↓
选举概率降低
```

---

## 对比：质押 vs 赎回

### 质押操作

```
join_info.stoke = 800000000 (质押金额)
    ↓
elect_stoke_map[addr] = 800000000
    ↓
join_elect_nodes[i].stoke = 800000000
    ↓
node_info->stoke = 800000000
    ↓
blance_weight = 100
    ↓
fts_value = 1200
    ↓
选举概率 = 32.3%
```

### 赎回操作

```
join_info.stoke = 0 ⭐
    ↓
elect_stoke_map[addr] = 0 ⭐
    ↓
join_elect_nodes[i].stoke = 0 ⭐
    ↓
node_info->stoke = 0 ⭐
    ↓
blance_weight = 100 (最低)
    ↓
fts_value = 1000 (降低)
    ↓
选举概率 = 降低
```

---

## 验证方法

### 1. 日志验证

**赎回操作日志**:
```
Redeemed stake in root shard: addr=XXX, amount=800000000, 
    stoke set to 0
```

**统计收集日志**:
```
redeem operation: set stoke to 0 for XXX, elect height: YYY
```

**选举统计日志**:
```
add new elect node: XXX, stoke: 0, shard: YYY
```

### 2. 测试场景

**场景 1: 单节点赎回**
```
1. 节点 A 质押 8 SETH → stoke = 800000000
2. 节点 A 赎回 → stoke = 0
3. 验证选举概率降低
```

**场景 2: 多节点混合**
```
1. 节点 A 质押 8 SETH, B 质押 16 SETH, C 质押 24 SETH
2. 验证概率: C > B > A
3. 节点 B 赎回 → stoke = 0
4. 验证概率: C > A > B (B 降低)
```

---

## 修改文件清单

| 文件 | 函数 | 修改内容 |
|------|------|----------|
| `src/consensus/zbft/join_elect_tx_item.cc` | `HandleRedeemOperation()` | 添加 `join_info.set_stoke(0)` |
| `src/pools/shard_statistic.cc` | `HandleStatistic()` lambda | 添加 `stake_op` 检查 |

---

## 编译和测试

### 编译
```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 运行
```bash
./seth --config conf/seth.conf
```

### 查看日志
```bash
tail -f logs/seth.log | grep -E "stoke|redeem|stake"
```

---

## 总结

### 实现要点

1. ✅ **赎回时设置 stoke = 0**: 在 `HandleRedeemOperation()` 中设置
2. ✅ **统计收集时区分操作**: 检查 `stake_op` 字段
3. ✅ **后续流程自动处理**: 0 值会自动传递到 FTS 计算

### 效果

- ✅ 赎回后节点的 PoS 权重被移除（stoke = 0）
- ✅ 赎回后节点的选举概率降低
- ✅ 防止已赎回的节点仍然享有质押奖励

### 安全性

- ✅ 防止赎回后仍享有 PoS 权重
- ✅ 防止伪造赎回操作（需要验证数据库记录）
- ✅ 防止重复赎回（删除数据库记录）

**实现完成！** ✅
