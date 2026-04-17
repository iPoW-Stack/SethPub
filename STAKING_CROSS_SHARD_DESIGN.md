# 质押跨分片架构设计

## 架构变更概述

### 当前问题
- 质押和赎回在本地分片处理
- 没有统一的质押信息管理
- 选举时无法获取全局质押信息

### 新架构
- **质押和赎回都通过 `join_info` 操作**
- **作为跨分片交易发送到 root 分片**
- **在 `kGlobalPoolIndex` 中处理**
- **Root 分片统一管理所有质押信息**
- **选举时作为 PoS 因子参与计算**

## 详细设计

### 1. Protocol Buffer 修改

#### bls.proto - 添加操作类型

```protobuf
message JoinElectInfo {
    optional uint32 shard_id = 1;
    optional uint32 member_idx = 2;
    optional uint32 change_idx = 3;
    optional VerifyVecBrdReq g2_req = 4;
    optional bytes addr = 5;
    optional uint64 stoke = 6;
    optional bytes public_key = 7;
    optional uint64 stake_amount = 8;
    optional uint64 stake_elect_height = 9;
    optional uint64 total_staked = 10;
    
    // 新增字段
    optional StakeOperation stake_op = 11 [default = STAKE_OP_NONE];  // 质押操作类型
    optional uint64 stake_timestamp = 12;  // 质押时间戳（用于锁定期计算）
}

enum StakeOperation {
    STAKE_OP_NONE = 0;      // 无质押操作（普通 join_elect）
    STAKE_OP_STAKE = 1;     // 质押操作
    STAKE_OP_REDEEM = 2;    // 赎回操作
}
```

### 2. 交易流程

#### 2.1 质押流程

```
用户节点 (Shard X)
    ↓
配置 stake_units = 1
    ↓
SendJoinElectTransaction()
    ├─ 设置 stake_op = STAKE_OP_STAKE
    ├─ 设置 stake_amount = 8 * 10^8
    ├─ 设置 stake_timestamp = current_timestamp
    └─ 发送到 kGlobalPoolIndex
        ↓
Root 分片 (kGlobalPoolIndex)
    ↓
JoinElectTxItem::HandleTx()
    ├─ 检测到 stake_op = STAKE_OP_STAKE
    ├─ 验证金额（8 * 10^8 的倍数）
    ├─ 检查余额
    ├─ 获取现有质押（如果有）
    ├─ 计算 total_staked = existing + new
    ├─ 转账到 root 分片池地址
    ├─ 保存质押信息到 root 数据库
    │   └─ SaveStakeInfo(addr, total_staked, timestamp, ...)
    └─ 更新 JoinElectInfo.total_staked
        ↓
选举时使用 total_staked 作为 PoS 因子
```

#### 2.2 赎回流程

```
用户节点 (Shard X)
    ↓
发送赎回请求
    ↓
SendRedeemStakeTransaction()
    ├─ 设置 stake_op = STAKE_OP_REDEEM
    ├─ stake_amount = 0（赎回不需要金额）
    └─ 发送到 kGlobalPoolIndex
        ↓
Root 分片 (kGlobalPoolIndex)
    ↓
JoinElectTxItem::HandleTx()
    ├─ 检测到 stake_op = STAKE_OP_REDEEM
    ├─ 获取质押信息
    ├─ 验证锁定期（current_timestamp - stake_timestamp >= 604,800）
    ├─ 从 root 池地址转回用户地址
    ├─ 删除质押信息
    └─ 通过跨分片交易返回资金到用户分片
```

### 3. 代码修改

#### 3.1 network_init.cc - 发送质押交易

```cpp
void NetworkInit::SendJoinElectTransaction() {
    // ... 现有代码 ...
    
    bls::protobuf::JoinElectInfo join_info;
    
    // 读取质押配置
    uint64_t stake_units = 0;
    conf_.Get("seth", "stake_units", stake_units);
    
    if (stake_units > 0) {
        // 质押操作
        static const uint64_t kMinStakeUnit = 8 * 100000000llu;
        uint64_t stake_amount = stake_units * kMinStakeUnit;
        
        join_info.set_stake_op(bls::protobuf::STAKE_OP_STAKE);
        join_info.set_stake_amount(stake_amount);
        join_info.set_stake_timestamp(common::TimeUtils::TimestampSeconds());
        
        SETH_INFO("Sending stake transaction: %lu coins to root shard", stake_amount);
    } else {
        // 普通 join_elect
        join_info.set_stake_op(bls::protobuf::STAKE_OP_NONE);
    }
    
    // 发送到 kGlobalPoolIndex（root 分片）
    msg.set_des_dht_key(dht_key.StrKey());
    // ... 发送逻辑 ...
}

void NetworkInit::SendRedeemStakeTransaction() {
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    // ... 设置消息头 ...
    
    bls::protobuf::JoinElectInfo join_info;
    join_info.set_stake_op(bls::protobuf::STAKE_OP_REDEEM);
    join_info.set_stake_amount(0);  // 赎回不需要金额
    join_info.set_addr(security_->GetAddress());
    
    // 发送到 kGlobalPoolIndex（root 分片）
    new_tx->set_value(SerializeDeterministic(join_info));
    network::Route::Instance()->Send(msg_ptr);
    
    SETH_INFO("Sending redeem transaction to root shard");
}
```

#### 3.2 join_elect_tx_item.cc - 处理质押和赎回

```cpp
int JoinElectTxItem::HandleTx(...) {
    // ... 现有验证逻辑 ...
    
    bls::protobuf::JoinElectInfo join_info;
    if (!join_info.ParseFromString(tx_info->value())) {
        break;
    }
    
    // 检查操作类型
    if (join_info.has_stake_op()) {
        switch (join_info.stake_op()) {
        case bls::protobuf::STAKE_OP_STAKE:
            return HandleStakeOperation(join_info, view_block, ...);
        case bls::protobuf::STAKE_OP_REDEEM:
            return HandleRedeemOperation(join_info, view_block, ...);
        default:
            // 普通 join_elect
            break;
        }
    }
    
    // ... 现有 join_elect 逻辑 ...
}

int JoinElectTxItem::HandleStakeOperation(
        const bls::protobuf::JoinElectInfo& join_info,
        view_block::protobuf::ViewBlockItem& view_block,
        ...) {
    
    // 只在 root 分片处理
    if (view_block.qc().network_id() != network::kRootCongressNetworkId) {
        SETH_ERROR("Stake operation must be processed in root shard");
        return kConsensusError;
    }
    
    // 只在 kGlobalPoolIndex 处理
    if (view_block.qc().pool_index() != common::kGlobalPoolIndex) {
        SETH_ERROR("Stake operation must be processed in global pool");
        return kConsensusError;
    }
    
    uint64_t stake_amount = join_info.stake_amount();
    
    // 验证金额
    static const uint64_t kMinStakeUnit = 8 * 100000000llu;
    if (stake_amount % kMinStakeUnit != 0) {
        SETH_ERROR("Invalid stake amount: %lu", stake_amount);
        return kConsensusError;
    }
    
    // 检查余额（跨分片）
    auto& from = address_info->addr();
    if (from_balance < stake_amount + gas_used * block_tx.gas_price()) {
        SETH_ERROR("Insufficient balance for stake");
        return kConsensusAccountBalanceError;
    }
    
    // 获取现有质押
    uint64_t existing_stake = 0;
    uint64_t existing_timestamp = 0;
    prefix_db_->GetStakeInfo(from, &existing_stake, &existing_timestamp, ...);
    
    // 计算总质押
    uint64_t total_staked = existing_stake + stake_amount;
    
    // 扣除质押金额
    from_balance -= stake_amount + gas_used * block_tx.gas_price();
    
    // 转到 root 分片池地址
    std::string root_pool_address = GetRootStakePoolAddress();
    uint64_t pool_balance = 0;
    GetTempAccountBalance(seth_host, root_pool_address, acc_balance_map, &pool_balance, ...);
    pool_balance += stake_amount;
    acc_balance_map[root_pool_address]->set_balance(pool_balance);
    
    // 保存质押信息（在 root 分片数据库）
    prefix_db_->SaveStakeInfo(
        from,
        total_staked,
        join_info.stake_timestamp(),  // 使用时间戳
        view_block.block_info().height()
    );
    
    // 更新 join_info 用于选举
    join_info.set_total_staked(total_staked);
    join_info.set_stoke(total_staked);  // 用于 PoS 计算
    
    auto* block_join_info = view_block.mutable_block_info()->add_joins();
    *block_join_info = join_info;
    
    SETH_INFO("Stake processed in root shard: addr=%s, amount=%lu, total=%lu",
        common::Encode::HexEncode(from).c_str(), stake_amount, total_staked);
    
    return kConsensusSuccess;
}

int JoinElectTxItem::HandleRedeemOperation(
        const bls::protobuf::JoinElectInfo& join_info,
        view_block::protobuf::ViewBlockItem& view_block,
        ...) {
    
    // 只在 root 分片处理
    if (view_block.qc().network_id() != network::kRootCongressNetworkId) {
        SETH_ERROR("Redeem operation must be processed in root shard");
        return kConsensusError;
    }
    
    auto& from = address_info->addr();
    
    // 获取质押信息
    uint64_t total_staked = 0;
    uint64_t stake_timestamp = 0;
    if (!prefix_db_->GetStakeInfo(from, &total_staked, &stake_timestamp, ...)) {
        SETH_ERROR("No stake info found for address: %s",
            common::Encode::HexEncode(from).c_str());
        return kConsensusError;
    }
    
    // 验证锁定期（604,800 秒 = 7天）
    static const uint64_t kStakeLockSeconds = 1008 * 600;
    uint64_t current_timestamp = view_block.block_info().timestamp();
    uint64_t seconds_passed = current_timestamp - stake_timestamp;
    
    if (seconds_passed < kStakeLockSeconds) {
        SETH_ERROR("Stake lock period not passed: %lu/%lu seconds",
            seconds_passed, kStakeLockSeconds);
        return kConsensusError;
    }
    
    // 从 root 池地址转回
    std::string root_pool_address = GetRootStakePoolAddress();
    uint64_t pool_balance = 0;
    GetTempAccountBalance(seth_host, root_pool_address, acc_balance_map, &pool_balance, ...);
    
    if (pool_balance < total_staked) {
        SETH_ERROR("Insufficient pool balance");
        return kConsensusError;
    }
    
    // 扣除 gas
    from_balance -= gas_used * block_tx.gas_price();
    
    // 转账（跨分片）
    pool_balance -= total_staked;
    from_balance += total_staked;
    
    acc_balance_map[root_pool_address]->set_balance(pool_balance);
    acc_balance_map[from]->set_balance(from_balance);
    
    // 删除质押信息
    prefix_db_->RemoveStakeInfo(from);
    
    SETH_INFO("Redeem processed in root shard: addr=%s, amount=%lu, seconds_passed=%lu",
        common::Encode::HexEncode(from).c_str(), total_staked, seconds_passed);
    
    return kConsensusSuccess;
}
```

#### 3.3 elect_tx_item.cc - 选举时使用质押信息

```cpp
void ElectTxItem::DoElect(...) {
    // ... 现有选举逻辑 ...
    
    // 获取候选节点
    for (int32_t i = 0; i < elect_statistic_.join_elect_nodes_size(); ++i) {
        auto& join_node = elect_statistic_.join_elect_nodes(i);
        auto node_info = std::make_shared<ElectNodeInfo>();
        
        // 使用质押信息作为 PoS 因子
        // stoke 字段现在包含 total_staked
        node_info->stoke = join_node.stoke();  // 这是 total_staked
        
        // PoS 权重计算
        // 质押越多，权重越高，被选为领导者的概率越大
        node_info->pos_weight = CalculatePosWeight(node_info->stoke);
        
        // ... 其他因子 ...
        
        elect_nodes.push_back(node_info);
    }
    
    // FTS 算法使用 stoke（即 total_staked）
    // 质押多的节点有更高的概率被选中
    FollowTheSatoshi(elect_nodes, random_seed);
    
    // ... 生成选举结果 ...
}

uint64_t ElectTxItem::CalculatePosWeight(uint64_t staked_amount) {
    // PoS 权重计算公式
    // 可以是线性、对数或其他函数
    
    // 示例：线性权重
    // 每 8 SETH 增加 1 个权重单位
    static const uint64_t kMinStakeUnit = 8 * 100000000llu;
    return staked_amount / kMinStakeUnit;
    
    // 或者：对数权重（避免大户垄断）
    // return log2(staked_amount / kMinStakeUnit + 1);
}
```

### 4. 数据库修改

#### 4.1 Root 分片数据库

```cpp
// prefix_db.h - Root 分片专用

// 保存质押信息（只在 root 分片）
void SaveStakeInfo(
    const std::string& address,
    uint64_t total_staked,
    uint64_t stake_timestamp,  // 使用时间戳
    uint64_t stake_block_height
);

// 获取质押信息（只在 root 分片）
bool GetStakeInfo(
    const std::string& address,
    uint64_t* total_staked,
    uint64_t* stake_timestamp,
    uint64_t* stake_block_height
);

// 删除质押信息（只在 root 分片）
void RemoveStakeInfo(const std::string& address);

// 获取所有质押信息（用于选举）
std::map<std::string, uint64_t> GetAllStakeInfo();
```

### 5. 跨分片交易处理

#### 5.1 质押资金流动

```
用户分片 (Shard X)
    ↓
用户账户余额 -= stake_amount
    ↓
跨分片交易 → Root 分片
    ↓
Root 分片池地址 += stake_amount
    ↓
记录质押信息
```

#### 5.2 赎回资金流动

```
Root 分片
    ↓
Root 分片池地址 -= total_staked
    ↓
跨分片交易 → 用户分片 (Shard X)
    ↓
用户账户余额 += total_staked
```

### 6. 工具函数

```cpp
// utils.cc

// 获取 root 分片质押池地址
std::string GetRootStakePoolAddress() {
    // Root 分片的固定质押池地址
    static const std::string kRootStakePoolSeed = "ROOT_STAKE_POOL_ADDRESS";
    std::string pool_address = common::Hash::Hash256(kRootStakePoolSeed);
    return pool_address.substr(0, kUnicastAddressLength);
}
```

### 7. 配置文件

```ini
[seth]
# 质押单位（每单位 = 8 SETH）
stake_units = 1

# 是否启用质押功能
enable_staking = true

# 赎回操作（通过命令行或 RPC）
# redeem_stake = true
```

### 8. 优势

#### 8.1 统一管理
- ✅ Root 分片统一管理所有质押信息
- ✅ 选举时可以获取全局质押数据
- ✅ 避免分片间数据不一致

#### 8.2 安全性
- ✅ 质押资金在 root 分片，更安全
- ✅ 跨分片交易有共识保证
- ✅ 锁定期在 root 分片验证

#### 8.3 可扩展性
- ✅ 支持更复杂的 PoS 机制
- ✅ 可以添加质押奖励
- ✅ 可以实现委托质押

### 9. 实现步骤

#### 阶段 1: Protocol Buffer 修改
- [ ] 在 `JoinElectInfo` 添加 `stake_op` 字段
- [ ] 添加 `StakeOperation` 枚举
- [ ] 添加 `stake_timestamp` 字段
- [ ] 编译 protobuf

#### 阶段 2: 质押交易发送
- [ ] 修改 `SendJoinElectTransaction()` 支持质押
- [ ] 添加 `SendRedeemStakeTransaction()` 函数
- [ ] 设置交易发送到 `kGlobalPoolIndex`

#### 阶段 3: Root 分片处理
- [ ] 修改 `JoinElectTxItem::HandleTx()` 检测操作类型
- [ ] 实现 `HandleStakeOperation()` 处理质押
- [ ] 实现 `HandleRedeemOperation()` 处理赎回
- [ ] 添加 root 分片池地址管理

#### 阶段 4: 数据库接口
- [ ] 实现 `SaveStakeInfo()` 在 root 分片
- [ ] 实现 `GetStakeInfo()` 在 root 分片
- [ ] 实现 `RemoveStakeInfo()` 在 root 分片
- [ ] 实现 `GetAllStakeInfo()` 用于选举

#### 阶段 5: 选举集成
- [ ] 修改 `DoElect()` 使用质押信息
- [ ] 实现 `CalculatePosWeight()` 计算 PoS 权重
- [ ] 更新 FTS 算法使用 `total_staked`

#### 阶段 6: 跨分片交易
- [ ] 实现质押资金跨分片转移
- [ ] 实现赎回资金跨分片返回
- [ ] 测试跨分片交易正确性

#### 阶段 7: 测试和文档
- [ ] 单元测试
- [ ] 集成测试
- [ ] 跨分片测试
- [ ] 更新文档

### 10. 测试场景

#### 场景 1: 单分片质押
```
Shard 1 节点质押 8 SETH
    ↓
发送到 Root 分片 kGlobalPoolIndex
    ↓
Root 分片记录质押信息
    ↓
选举时使用质押信息
```

#### 场景 2: 多分片质押
```
Shard 1 节点质押 8 SETH
Shard 2 节点质押 16 SETH
Shard 3 节点质押 24 SETH
    ↓
所有质押发送到 Root 分片
    ↓
Root 分片统一管理
    ↓
选举时根据质押权重分配
```

#### 场景 3: 追加质押
```
Shard 1 节点第一次质押 8 SETH
    ↓
Root 分片记录: total_staked = 8 SETH
    ↓
Shard 1 节点第二次质押 8 SETH
    ↓
Root 分片更新: total_staked = 16 SETH
    ↓
选举时使用 16 SETH 计算权重
```

#### 场景 4: 赎回
```
Shard 1 节点发送赎回请求
    ↓
Root 分片验证锁定期
    ↓
Root 分片转账回 Shard 1
    ↓
删除质押信息
```

### 11. 注意事项

#### 11.1 跨分片延迟
- 质押和赎回需要跨分片通信
- 可能有延迟，需要用户等待确认

#### 11.2 Root 分片负载
- 所有质押操作都在 root 分片处理
- 需要确保 root 分片性能足够

#### 11.3 数据一致性
- Root 分片是质押信息的唯一来源
- 其他分片不应缓存质押信息

#### 11.4 安全性
- Root 分片池地址需要特殊保护
- 防止未授权访问

### 12. 未来优化

#### 12.1 质押奖励
- 质押期间获得奖励
- 奖励分配机制

#### 12.2 委托质押
- 支持委托给其他节点
- 委托关系管理

#### 12.3 动态调整
- 根据网络状态调整锁定期
- 根据质押量调整奖励

#### 12.4 惩罚机制
- 恶意行为扣除质押
- Slashing 机制

## 总结

这个设计将质押功能完全集成到跨分片架构中：
- ✅ 使用 `join_info` 统一接口
- ✅ Root 分片统一管理
- ✅ 选举时作为 PoS 因子
- ✅ 支持跨分片交易
- ✅ 保证数据一致性

这是一个更符合分片区块链架构的设计！
