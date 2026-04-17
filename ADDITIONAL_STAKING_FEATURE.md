# 追加质押功能实现总结

## 概述

在原有质押功能基础上，增加了**追加质押**功能，允许节点多次质押以增加总质押金额，同时每次追加质押都会重置锁定期。

## 核心特性

### 1. 追加质押机制

- ✅ **支持多次质押**: 节点可以多次发送JoinElect交易追加质押
- ✅ **累计总金额**: 每次追加质押都会累加到总质押金额
- ✅ **锁定期重置**: 每次追加质押都会将锁定期重置为新的1008个epoch
- ✅ **FTS权重计算**: 使用总质押金额（total_staked）计算FTS权重

### 2. 锁定期管理

- **初始质押**: 锁定期从第一次质押的elect_height开始计算
- **追加质押**: 每次追加质押都会更新stake_elect_height，锁定期重新开始
- **赎回条件**: 必须从最后一次质押（包括追加）开始计算，满1008个epoch后才能赎回
- **赎回金额**: 赎回时返还全部累计质押金额

### 3. 数据结构变更

#### Protobuf定义
```protobuf
message JoinElectInfo {
    optional uint32 shard_id = 1;
    optional uint32 member_idx = 2;
    optional uint32 change_idx = 3;
    optional VerifyVecBrdReq g2_req = 4;
    optional bytes addr = 5;
    optional uint64 stoke = 6;
    optional bytes public_key = 7;
    optional uint64 stake_amount = 8;        // 本次质押金额
    optional uint64 stake_elect_height = 9;  // 最后一次质押的elect_height（重置锁定期）
    optional uint64 total_staked = 10;       // 累计总质押金额（用于FTS计算）
}
```

## 实现细节

### 1. 质押流程（支持追加）

```cpp
// 在 join_elect_tx_item.cc 的 HandleTx() 中

// 1. 检查是否存在旧的质押记录
uint64_t existing_stake = 0;
uint64_t existing_elect_height = 0;
uint32_t existing_pool_index = 0;
uint64_t existing_block_height = 0;
bool has_existing_stake = prefix_db_->GetStakeInfo(
    from, &existing_stake, &existing_elect_height, 
    &existing_pool_index, &existing_block_height);

// 2. 计算总质押金额
uint64_t total_staked = existing_stake + stake_amount;

// 3. 转账到pool地址
from_balance -= stake_amount;
pool_balance += stake_amount;

// 4. 保存更新后的质押信息（重置锁定期）
prefix_db_->SaveStakeInfo(
    from,
    total_staked,                      // 保存累计总金额
    join_info.stake_elect_height(),    // 重置锁定期起点
    pool_index,
    view_block.block_info().height());

// 5. 设置total_staked用于FTS计算
join_info.set_total_staked(total_staked);
```

### 2. 赎回流程（返还全部）

```cpp
// 在 redeem_stake_tx_item.cc 的 HandleTx() 中

// 1. 获取质押信息（包含累计总金额）
uint64_t total_stake_amount = 0;
uint64_t stake_elect_height = 0;
prefix_db_->GetStakeInfo(from, &total_stake_amount, &stake_elect_height, ...);

// 2. 验证锁定期（从最后一次质押开始）
uint64_t epochs_passed = current_elect_height - stake_elect_height;
if (epochs_passed < kStakeLockEpochs) {
    // 锁定期未满，拒绝赎回
    return kConsensusError;
}

// 3. 从pool地址转回全部累计质押金额
pool_balance -= total_stake_amount;
from_balance += total_stake_amount;

// 4. 删除质押信息
prefix_db_->RemoveStakeInfo(from);
```

## 使用示例

### 场景1: 初始质押

```ini
# 配置文件
[seth]
stake_units = 1  # 质押1个单位 (8 SETH)
```

**结果**:
- 质押金额: 800,000,000 (8 SETH)
- 总质押: 800,000,000 (8 SETH)
- 锁定期起点: elect_height = 12345
- 可赎回时间: elect_height >= 13353 (12345 + 1008)

### 场景2: 追加质押

```ini
# 配置文件（第二次质押）
[seth]
stake_units = 2  # 追加2个单位 (16 SETH)
```

**结果**:
- 本次质押: 1,600,000,000 (16 SETH)
- 总质押: 2,400,000,000 (24 SETH = 8 + 16)
- 锁定期起点: elect_height = 12500 (重置！)
- 可赎回时间: elect_height >= 13508 (12500 + 1008)

### 场景3: 赎回

**条件**:
- 当前 elect_height = 13508
- 距离最后一次质押: 13508 - 12500 = 1008 epochs ✅

**结果**:
- 赎回金额: 2,400,000,000 (24 SETH，全部累计质押)
- 质押记录: 已删除

## 日志示例

### 初始质押
```
[INFO] Initial stake: 800000000 coins (8 SETH) to pool 5 address 0x1234..., elect_height: 12345
```

### 追加质押
```
[INFO] Additional stake: added 1600000000 coins (total now: 2400000000 = 24 SETH) to pool 5 address 0x1234..., 
       lock period reset to elect_height: 12500 (previous: 12345)
```

### 赎回成功
```
[INFO] Redeemed total 2400000000 coins (24 SETH) from pool 5 address 0x1234... to 0x5678..., 
       epochs passed: 1008, stake_elect_height: 12500, current_elect_height: 13508
```

### 赎回失败（锁定期未满）
```
[ERROR] Stake lock period not passed: 500/1008 epochs
```

## FTS权重计算

FTS（Follow The Satoshi）算法在计算节点权重时，使用 `total_staked` 字段：

```cpp
// 伪代码示例
uint64_t node_weight = base_weight + (total_staked / kMinStakeUnit);

// 例如:
// 节点A: total_staked = 800,000,000 (8 SETH = 1单位)
//        weight = base_weight + 1
//
// 节点B: total_staked = 2,400,000,000 (24 SETH = 3单位)
//        weight = base_weight + 3
//
// 节点B的选举概率是节点A的3倍
```

## 安全考虑

### 1. 防止锁定期绕过
- ✅ 每次追加质押都重置锁定期
- ✅ 不能通过频繁小额追加来绕过锁定期限制

### 2. 防止重复赎回
- ✅ 赎回成功后立即删除质押记录
- ✅ 第二次赎回会因为找不到记录而失败

### 3. 余额验证
- ✅ 追加质押前检查账户余额
- ✅ 赎回前检查pool地址余额

### 4. 原子性保证
- ✅ 质押和余额更新在同一个交易中完成
- ✅ 失败时自动回滚

## 数据库接口

```cpp
// 保存/更新质押信息
// 参数说明:
// - total_stake_amount: 累计总质押金额（不是本次金额）
// - stake_elect_height: 最新的质押选举高度（每次追加时更新）
bool SaveStakeInfo(
    const std::string& address,
    uint64_t total_stake_amount,
    uint64_t stake_elect_height,
    uint32_t pool_index,
    uint64_t stake_block_height);

// 获取质押信息
// 返回值说明:
// - total_stake_amount: 累计总质押金额
// - stake_elect_height: 最后一次质押的选举高度
bool GetStakeInfo(
    const std::string& address,
    uint64_t* total_stake_amount,
    uint64_t* stake_elect_height,
    uint32_t* pool_index,
    uint64_t* stake_block_height);
```

## 测试用例

### 测试1: 单次质押和赎回
1. 质押1单位 (8 SETH)
2. 等待1008个epoch
3. 赎回成功，获得8 SETH

### 测试2: 追加质押和赎回
1. 质押1单位 (8 SETH)（elect_height = 100）
2. 等待500个epoch
3. 追加质押2单位 (16 SETH)（elect_height = 600，锁定期重置）
4. 等待1008个epoch（从600开始）
5. 赎回成功，获得24 SETH (8 + 16)

### 测试3: 锁定期未满
1. 质押1单位 (8 SETH)（elect_height = 100）
2. 等待500个epoch
3. 追加质押1单位 (8 SETH)（elect_height = 600，锁定期重置）
4. 等待500个epoch（总共1000个epoch，但从600开始只有500）
5. 赎回失败，提示锁定期未满

### 测试4: 余额不足
1. 账户余额: 10 SETH (1,000,000,000)
2. 质押1单位 (8 SETH): 800,000,000 ✅
3. 尝试追加2单位 (16 SETH): 1,600,000,000 ❌（余额不足）

## 优势

1. **灵活性**: 节点可以根据需要逐步增加质押
2. **安全性**: 锁定期重置防止绕过机制
3. **公平性**: FTS使用总质押金额，反映真实权重
4. **激励性**: 鼓励节点长期持有和增加质押

## 总结

追加质押功能为Seth区块链提供了更灵活的质押机制：

- ✅ **支持多次质押**: 累计增加总质押金额
- ✅ **锁定期重置**: 每次追加都重新计算锁定期
- ✅ **FTS权重**: 使用总质押金额计算选举权重
- ✅ **全额赎回**: 赎回时返还全部累计质押
- ✅ **安全可靠**: 完整的验证和错误处理机制

该功能增强了网络的经济激励机制，鼓励节点长期参与和增加质押，从而提高网络的安全性和稳定性。
