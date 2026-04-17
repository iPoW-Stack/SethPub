# 质押跨分片实现完成

## 实现概述

质押和赎回功能已完全集成到现有的 `join_info` 链路中，通过 root 分片统一管理。

## 核心变更

### 1. Protocol Buffer 修改

#### bls.proto
```protobuf
enum StakeOperation {
    STAKE_OP_NONE = 0;      // 无质押操作（普通 join_elect）
    STAKE_OP_STAKE = 1;     // 质押操作
    STAKE_OP_REDEEM = 2;    // 赎回操作
}

message JoinElectInfo {
    // ... 现有字段 ...
    optional StakeOperation stake_op = 11 [default = STAKE_OP_NONE];
    optional uint64 stake_timestamp = 12;  // 质押时间戳
}
```

### 2. 交易发送

#### network_init.cc

**质押交易**:
```cpp
void NetworkInit::SendJoinElectTransaction() {
    // ... 现有逻辑 ...
    
    uint64_t stake_units = 0;
    conf_.Get("seth", "stake_units", stake_units);
    
    if (stake_units > 0) {
        // 质押操作
        join_info.set_stake_op(bls::protobuf::STAKE_OP_STAKE);
        join_info.set_stake_amount(stake_units * 8 * 100000000llu);
        join_info.set_stake_timestamp(current_timestamp);
    } else {
        // 普通 join_elect
        join_info.set_stake_op(bls::protobuf::STAKE_OP_NONE);
    }
    
    // 发送到 root 分片
    network::Route::Instance()->Send(msg_ptr);
}
```

**赎回交易**:
```cpp
void NetworkInit::SendRedeemStakeTransaction() {
    // 创建 join_elect 消息
    bls::protobuf::JoinElectInfo join_info;
    join_info.set_stake_op(bls::protobuf::STAKE_OP_REDEEM);
    join_info.set_stake_amount(0);
    
    // 发送到 root 分片
    network::Route::Instance()->Send(msg_ptr);
}
```

### 3. Root 分片处理

#### join_elect_tx_item.cc

```cpp
int JoinElectTxItem::HandleTx(...) {
    // ... 现有验证 ...
    
    if (join_info.has_stake_op()) {
        switch (join_info.stake_op()) {
        case bls::protobuf::STAKE_OP_STAKE:
            return HandleStakeOperation(...);
        case bls::protobuf::STAKE_OP_REDEEM:
            return HandleRedeemOperation(...);
        default:
            // 普通 join_elect
            break;
        }
    }
    
    // ... 现有 join_elect 逻辑 ...
}
```

**质押处理**:
```cpp
int JoinElectTxItem::HandleStakeOperation(...) {
    // 1. 验证金额（8 * 10^8 的倍数）
    // 2. 检查余额
    // 3. 获取现有质押（支持追加）
    // 4. 计算 total_staked = existing + new
    // 5. 转账到 root 池地址
    // 6. 保存质押信息（使用时间戳）
    // 7. 更新 join_info.stoke = total_staked（用于 PoS）
    // 8. 添加到 block joins
}
```

**赎回处理**:
```cpp
int JoinElectTxItem::HandleRedeemOperation(...) {
    // 1. 获取质押信息
    // 2. 验证锁定期（current_timestamp - stake_timestamp >= 604,800）
    // 3. 从 root 池地址转回用户
    // 4. 删除质押信息
}
```

### 4. 数据库接口

#### prefix_db.h

```cpp
// 保存质押信息（24 字节）
void SaveStakeInfo(
    const std::string& address,
    uint64_t total_staked,      // 8 bytes
    uint64_t stake_timestamp,   // 8 bytes
    uint64_t stake_block_height // 8 bytes
);

// 获取质押信息
bool GetStakeInfo(
    const std::string& address,
    uint64_t* total_staked,
    uint64_t* stake_timestamp
);

// 删除质押信息
void RemoveStakeInfo(const std::string& address);
```

### 5. 工具函数

#### utils.cc

```cpp
// 获取 root 分片质押池地址
std::string GetRootStakePoolAddress() {
    static const std::string kRootStakePoolSeed = "ROOT_STAKE_POOL_ADDRESS_SEED";
    return Hash256(kRootStakePoolSeed).substr(0, kUnicastAddressLength);
}
```

## 数据流程

### 质押流程

```
用户节点 (Shard X)
    ↓
配置 stake_units = 1
    ↓
SendJoinElectTransaction()
    ├─ stake_op = STAKE_OP_STAKE
    ├─ stake_amount = 8 * 10^8
    └─ stake_timestamp = current_time
        ↓
发送到 Root 分片
        ↓
JoinElectTxItem::HandleTx()
    ├─ 检测 stake_op = STAKE_OP_STAKE
    └─ HandleStakeOperation()
        ├─ 验证金额
        ├─ 检查余额
        ├─ 获取现有质押
        ├─ total_staked = existing + new
        ├─ 转账到 root_pool_address
        ├─ SaveStakeInfo(addr, total_staked, timestamp, height)
        └─ join_info.stoke = total_staked
            ↓
选举时使用 stoke（即 total_staked）作为 PoS 权重
```

### 赎回流程

```
用户节点 (Shard X)
    ↓
SendRedeemStakeTransaction()
    ├─ stake_op = STAKE_OP_REDEEM
    └─ stake_amount = 0
        ↓
发送到 Root 分片
        ↓
JoinElectTxItem::HandleTx()
    ├─ 检测 stake_op = STAKE_OP_REDEEM
    └─ HandleRedeemOperation()
        ├─ GetStakeInfo(addr, &total_staked, &timestamp)
        ├─ 验证锁定期（current_time - timestamp >= 604,800）
        ├─ 从 root_pool_address 转回用户
        └─ RemoveStakeInfo(addr)
```

## 关键参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 最小质押单位 | 8 SETH | 8 * 10^8 coins |
| 锁定期 | 604,800 秒 | 1008 * 600 = 7天 |
| 锁定期计算 | 时间戳 | current_timestamp - stake_timestamp |
| 质押池地址 | Root 分片 | GetRootStakePoolAddress() |
| 追加质押 | 支持 | 累计 total_staked，重置锁定期 |
| PoS 权重 | total_staked | join_info.stoke = total_staked |

## 配置文件

```ini
[seth]
# 质押单位（每单位 = 8 SETH）
stake_units = 1

# 赎回操作（通过命令行或 RPC 调用）
# 调用 SendRedeemStakeTransaction()
```

## 选举集成

### elect_tx_item.cc

```cpp
void ElectTxItem::DoElect(...) {
    // 获取候选节点
    for (auto& join_node : elect_statistic_.join_elect_nodes()) {
        auto node_info = std::make_shared<ElectNodeInfo>();
        
        // stoke 字段现在包含 total_staked
        node_info->stoke = join_node.stoke();
        
        // PoS 权重计算
        node_info->pos_weight = CalculatePosWeight(node_info->stoke);
        
        elect_nodes.push_back(node_info);
    }
    
    // FTS 算法使用 stoke（即 total_staked）
    // 质押多的节点有更高的概率被选中
    FollowTheSatoshi(elect_nodes, random_seed);
}
```

## 修改的文件清单

### 核心逻辑 (4 个文件)
1. `src/protos/bls.proto` - 添加 StakeOperation 枚举和字段
2. `src/init/network_init.cc` - 质押和赎回交易发送
3. `src/init/network_init.h` - 添加 SendRedeemStakeTransaction 声明
4. `src/consensus/zbft/join_elect_tx_item.cc` - 处理质押和赎回
5. `src/consensus/zbft/join_elect_tx_item.h` - 添加处理函数声明

### 工具函数 (2 个文件)
6. `src/common/utils.h` - GetRootStakePoolAddress 声明
7. `src/common/utils.cc` - GetRootStakePoolAddress 实现

### 数据库接口 (1 个文件)
8. `src/protos/prefix_db.h` - 修改为使用时间戳

### 清理 (5 个文件)
9. `src/protos/pools.proto` - 移除 kRedeemStake
10. `src/pools/tx_pool_manager.cc` - 移除 kRedeemStake 处理
11. `src/consensus/hotstuff/block_acceptor.cc` - 移除 kRedeemStake
12. `src/consensus/hotstuff/hotstuff_manager.h` - 移除 include
13. `src/consensus/hotstuff/hotstuff_manager.cc` - 移除 kRedeemStake

### 删除的文件 (2 个)
14. ~~`src/consensus/zbft/redeem_stake_tx_item.h`~~ - 已删除
15. ~~`src/consensus/zbft/redeem_stake_tx_item.cc`~~ - 已删除

**总计：13 个文件修改，2 个文件删除**

## 优势

### 1. 统一管理
- ✅ Root 分片统一管理所有质押信息
- ✅ 选举时可以直接获取全局质押数据
- ✅ 避免分片间数据不一致

### 2. 简化架构
- ✅ 复用现有 join_elect 链路
- ✅ 不需要新的交易类型
- ✅ 代码更简洁

### 3. 安全性
- ✅ 质押资金在 root 分片，更安全
- ✅ 跨分片交易有共识保证
- ✅ 锁定期在 root 分片验证

### 4. PoS 集成
- ✅ `join_info.stoke` 直接用于选举
- ✅ 质押越多，权重越高
- ✅ 无缝集成到 FTS 算法

## 使用示例

### 质押

```bash
# 1. 配置质押
echo "stake_units = 1" >> seth.conf  # 质押 8 SETH

# 2. 启动节点（自动质押）
./seth --config seth.conf

# 日志输出：
# Sending stake transaction: 800000000 coins (1 units) to root shard
# Initial stake in root shard: addr=XXX, amount=800000000, timestamp=YYY
```

### 追加质押

```bash
# 修改配置
echo "stake_units = 2" >> seth.conf  # 再质押 8 SETH

# 重启节点
./seth --config seth.conf

# 日志输出：
# Additional stake in root shard: addr=XXX, added=800000000, total=1600000000
```

### 赎回

```bash
# 通过 RPC 或命令行调用
# network_init->SendRedeemStakeTransaction()

# 日志输出：
# Sent redeem stake transaction to root shard
# Redeemed stake in root shard: addr=XXX, amount=1600000000, seconds_passed=604800
```

## 测试场景

### 场景 1: 单分片质押
```
Shard 1 节点质押 8 SETH
    ↓
Root 分片记录: total_staked = 8 SETH
    ↓
选举时 stoke = 8 SETH
```

### 场景 2: 多分片质押
```
Shard 1: 8 SETH
Shard 2: 16 SETH
Shard 3: 24 SETH
    ↓
Root 分片统一管理
    ↓
选举时按质押权重分配
```

### 场景 3: 追加质押
```
第一次: 8 SETH (timestamp: T1)
第二次: 8 SETH (timestamp: T2)
    ↓
total_staked = 16 SETH
锁定期从 T2 开始
    ↓
T2 + 604,800 秒后可赎回 16 SETH
```

### 场景 4: 锁定期验证
```
质押时间: T1
尝试赎回: T1 + 300,000 秒
    ↓
验证失败: 300,000 < 604,800
    ↓
等待到 T1 + 604,800 秒
    ↓
赎回成功
```

## 编译和部署

### 1. 编译 Protobuf
```bash
# 编译 bls.proto 和 pools.proto
protoc --cpp_out=. src/protos/bls.proto
protoc --cpp_out=. src/protos/pools.proto
```

### 2. 编译项目
```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 3. 配置和启动
```bash
# 配置质押
echo "stake_units = 1" >> conf/seth.conf

# 启动节点
./seth --config conf/seth.conf
```

## 验证清单

- [x] Protocol Buffer 修改完成
- [x] 质押交易发送实现
- [x] 赎回交易发送实现
- [x] Root 分片质押处理
- [x] Root 分片赎回处理
- [x] 数据库接口更新
- [x] 工具函数实现
- [x] 清理旧代码
- [x] 删除不需要的文件
- [x] 代码编译通过
- [x] 无诊断错误

## 注意事项

### 1. Root 分片负载
- 所有质押操作都在 root 分片处理
- 需要确保 root 分片性能足够
- 可以考虑优化或分批处理

### 2. 跨分片延迟
- 质押和赎回需要跨分片通信
- 可能有延迟，需要用户等待确认
- 建议添加交易状态查询接口

### 3. 数据一致性
- Root 分片是质押信息的唯一来源
- 其他分片不应缓存质押信息
- 选举时从 root 分片获取最新数据

### 4. 安全性
- Root 分片池地址需要特殊保护
- 防止未授权访问
- 建议添加多重签名或其他安全机制

## 未来优化

### 1. 质押奖励
- 质押期间获得奖励
- 奖励分配机制
- 激励长期质押

### 2. 委托质押
- 支持委托给其他节点
- 委托关系管理
- 奖励分配

### 3. 动态调整
- 根据网络状态调整锁定期
- 根据质押量调整奖励
- 动态 PoS 权重

### 4. 惩罚机制
- 恶意行为扣除质押
- Slashing 机制
- 信誉系统

## 总结

质押功能已完全集成到现有的 join_info 链路中：

- ✅ 使用 `StakeOperation` 枚举区分操作类型
- ✅ 质押和赎回都通过 `kJoinElect` 交易
- ✅ Root 分片统一管理质押信息
- ✅ 使用时间戳计算锁定期（604,800 秒）
- ✅ 支持追加质押（累计 total_staked）
- ✅ `join_info.stoke` 用于 PoS 权重
- ✅ 无缝集成到选举系统
- ✅ 代码简洁，复用现有链路

**实现完成，可以开始测试！** 🎉
