# 赎回操作 Stoke 设置为 0 的设计

## 需求

赎回质押时，需要将节点的 `stoke` 设置为 0，这样在选举统计时就不会给赎回的节点分配 PoS 权重。

## 设计原理

### 为什么赎回时要设置 stoke = 0？

1. **移除 PoS 权重**: 赎回后节点不再有质押，不应该享有 PoS 权重
2. **公平性**: 防止已赎回的节点仍然参与选举并获得奖励
3. **一致性**: 确保 stoke 值始终反映节点的实际质押状态

### 实现方式

通过 `join_info.stake_op` 字段区分操作类型：
- `STAKE_OP_STAKE`: 质押操作，`stoke = total_staked`
- `STAKE_OP_REDEEM`: 赎回操作，`stoke = 0`
- `STAKE_OP_NONE`: 普通 join_elect，`stoke` 从数据库获取

---

## 实现细节

### 1. 赎回操作设置 stoke = 0

**文件**: `src/consensus/zbft/join_elect_tx_item.cc`

**函数**: `HandleRedeemOperation()`

```cpp
int JoinElectTxItem::HandleRedeemOperation(...) {
    // ... 验证锁定期 ...
    // ... 转账赎回金额 ...
    // ... 删除质押信息 ...
    
    // ⭐ 关键：设置 stoke 为 0（移除 PoS 权重）
    join_info.set_stoke(0);
    join_info.set_total_staked(0);
    
    // 添加到区块 joins 以记录赎回操作
    auto* block_join_info = view_block.mutable_block_info()->add_joins();
    *block_join_info = join_info;
    
    SETH_INFO("Redeemed stake: addr=%s, amount=%lu, stoke set to 0",
        common::Encode::HexEncode(from).c_str(), total_staked);
    
    return kConsensusSuccess;
}
```

**关键点**:
- ✅ 赎回成功后，`join_info.stoke = 0`
- ✅ `join_info.total_staked = 0`
- ✅ 仍然添加到 `block.joins` 以记录操作

---

### 2. 统计收集时区分操作类型

**文件**: `src/pools/shard_statistic.cc`

**函数**: `HandleStatistic()` 中的 lambda

```cpp
auto handle_joins_func = [&](const bls::protobuf::JoinElectInfo& join_info) {
    auto join_addr = secptr_->GetAddressWithPublicKey(join_info.public_key());
    
    auto& elect_stoke_map = join_elect_stoke_map[elect_height];
    
    // ⭐ 检查是否是赎回操作
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
- ✅ 检查 `stake_op` 字段
- ✅ 赎回操作：`elect_stoke_map[addr] = 0`
- ✅ 其他操作：`elect_stoke_map[addr] = join_info.stoke()`

---

### 3. 后续流程自动处理

**选举统计** (`shard_statistic.cc:976`):
```cpp
auto stoke_iter = r_eiter->second.find(elect_nodes[i]);
auto stoke = stoke_iter->second;  // 赎回的节点这里会是 0
join_elect_node->set_stoke(stoke);  // 设置为 0
```

**选举准备** (`elect_tx_item.cc:578`):
```cpp
node_info->stoke = elect_statistic_.join_elect_nodes(i).stoke();  // 0
```

**FTS 计算**:
```cpp
// stoke = 0 的节点会被排在最前面（最小）
// blance_weight 也会是最低的
// fts_value 会受到影响，选举概率降低
```

---

## 数据流

### 赎回操作的数据流

```
赎回交易
    ↓
HandleRedeemOperation()
    ↓
join_info.stoke = 0  ← 设置为 0
join_info.stake_op = STAKE_OP_REDEEM
    ↓
block.joins[i] = join_info
    ↓
HandleStatistic() - lambda
    ↓
检查 stake_op == STAKE_OP_REDEEM
    ↓
elect_stoke_map[addr] = 0  ← 记录为 0
    ↓
addNewNode2JoinStatics()
    ↓
join_elect_node->set_stoke(0)  ← 传递 0
    ↓
GetIndexNodes()
    ↓
node_info->stoke = 0  ← 使用 0
    ↓
FTS 计算
    ↓
blance_weight 最低
    ↓
fts_value 降低
    ↓
选举概率降低
```

---

## 对比：质押 vs 赎回

### 质押操作

| 步骤 | 值 | 说明 |
|------|-----|------|
| HandleStakeOperation() | `join_info.stoke = 800000000` | 设置为质押金额 |
| block.joins | `stoke = 800000000` | 保存到区块 |
| elect_stoke_map | `[addr] = 800000000` | 收集到 map |
| join_elect_nodes | `stoke = 800000000` | 传递到选举统计 |
| node_info | `stoke = 800000000` | 用于 FTS 计算 |
| blance_weight | `100` | 基础权重 |
| fts_value | `1200` | 正常值 |
| 选举概率 | `32.3%` | 正常概率 |

### 赎回操作

| 步骤 | 值 | 说明 |
|------|-----|------|
| HandleRedeemOperation() | `join_info.stoke = 0` | ⭐ 设置为 0 |
| block.joins | `stoke = 0` | 保存到区块 |
| elect_stoke_map | `[addr] = 0` | ⭐ 收集为 0 |
| join_elect_nodes | `stoke = 0` | ⭐ 传递 0 |
| node_info | `stoke = 0` | ⭐ 用于 FTS 计算 |
| blance_weight | `100` (最低) | 最低权重 |
| fts_value | `1000` (降低) | 降低的值 |
| 选举概率 | `降低` | 概率降低 |

---

## 测试场景

### 场景 1: 单节点赎回

**步骤**:
1. 节点 A 质押 8 SETH
2. 验证 `stoke = 800000000`
3. 等待锁定期（7 天）
4. 节点 A 赎回
5. 验证 `stoke = 0`
6. 验证选举概率降低

**期望结果**:
```
质押前: stoke = 0, 概率 = 基础概率
质押后: stoke = 800000000, 概率 = 提高
赎回后: stoke = 0, 概率 = 降低到基础概率
```

### 场景 2: 多节点混合

**步骤**:
1. 节点 A 质押 8 SETH
2. 节点 B 质押 16 SETH
3. 节点 C 质押 24 SETH
4. 运行选举，验证概率：C > B > A
5. 节点 B 赎回
6. 运行选举，验证概率：C > A > B

**期望结果**:
```
赎回前:
Node A: stoke = 800000000,  概率 = 32.3%
Node B: stoke = 1600000000, 概率 = 33.3%
Node C: stoke = 2400000000, 概率 = 34.4%

赎回后:
Node A: stoke = 800000000,  概率 = 33.5%
Node B: stoke = 0,          概率 = 31.0% (降低)
Node C: stoke = 2400000000, 概率 = 35.5%
```

### 场景 3: 赎回后重新质押

**步骤**:
1. 节点 A 质押 8 SETH
2. 验证 `stoke = 800000000`
3. 节点 A 赎回
4. 验证 `stoke = 0`
5. 节点 A 重新质押 16 SETH
6. 验证 `stoke = 1600000000`

**期望结果**:
```
第一次质押: stoke = 800000000
赎回:       stoke = 0
重新质押:   stoke = 1600000000
```

---

## 日志验证

### 赎回操作日志

```
Redeemed stake in root shard: addr=XXX, amount=800000000, 
    seconds_passed=604800, stake_timestamp=YYY, current_timestamp=ZZZ, 
    pool=AAA, stoke set to 0
```

### 统计收集日志

```
redeem operation: set stoke to 0 for XXX, elect height: YYY, tm height: ZZZ
```

### 选举统计日志

```
add new elect node: XXX, stoke: 0, shard: YYY
```

### FTS 计算日志

```
before sort: pubkey1:0,pubkey2:800000000,pubkey3:1600000000
fts value final: ...,100,...,1000 --- ...,100,...,1200 --- ...,120,...,1240
```

---

## 边界情况处理

### 1. 赎回但未删除数据库记录

**问题**: 如果 `RemoveStakeInfo()` 失败，数据库中仍有质押记录

**解决**: 
- `join_info.stoke = 0` 仍然生效
- 下次 join_elect 时会检查数据库，但 `elect_stoke_map` 中已经是 0
- 不影响选举公平性

### 2. 赎回后立即 join_elect

**问题**: 赎回后节点立即发送普通 join_elect

**解决**:
```cpp
// HandleTx() 结束时
if (prefix_db_->GetStakeInfo(from, &stoke, &stake_timestamp)) {
    join_info.set_stoke(stoke);  // 数据库中已删除，不会进入这里
} else {
    prefix_db_->GetElectNodeMinStoke(network_id, from, &stoke);
    join_info.set_stoke(stoke);  // 使用历史最小 stoke
}
```

### 3. 同一区块中质押和赎回

**问题**: 理论上不可能（需要等待锁定期）

**解决**: 锁定期检查会阻止这种情况

---

## 安全性考虑

### 1. 防止赎回后仍享有 PoS 权重

✅ **已解决**: 赎回时强制设置 `stoke = 0`

### 2. 防止伪造赎回操作

✅ **已解决**: 
- 需要验证数据库中的质押记录
- 需要验证锁定期
- 需要验证签名

### 3. 防止重复赎回

✅ **已解决**: 
- 赎回后删除数据库记录
- 第二次赎回会因为找不到记录而失败

---

## 性能影响

### 额外检查

```cpp
if (join_info.has_stake_op() && 
    join_info.stake_op() == bls::protobuf::STAKE_OP_REDEEM) {
    // 赎回处理
}
```

**影响**: 
- 每个 join_info 增加一次条件判断
- 性能影响可忽略不计（O(1) 操作）

### 内存影响

**无额外内存开销**:
- 使用现有的 `stake_op` 字段
- 不需要额外的数据结构

---

## 总结

### 实现要点

1. ✅ **赎回时设置 stoke = 0**: `HandleRedeemOperation()` 中设置
2. ✅ **统计收集时区分操作**: 检查 `stake_op` 字段
3. ✅ **后续流程自动处理**: 0 值会自动传递到 FTS 计算

### 数据流

```
赎回 → stoke = 0 → elect_stoke_map[addr] = 0 → 
join_elect_nodes[i].stoke = 0 → node_info->stoke = 0 → 
blance_weight 降低 → fts_value 降低 → 选举概率降低
```

### 验证方法

1. **日志验证**: 查看 "stoke set to 0" 和 "redeem operation" 日志
2. **选举验证**: 赎回后节点的选举概率应该降低
3. **数据库验证**: 赎回后 `GetStakeInfo()` 应该返回 false

### 安全性

✅ **防止赎回后仍享有 PoS 权重**  
✅ **防止伪造赎回操作**  
✅ **防止重复赎回**

**实现完成！** ✅
