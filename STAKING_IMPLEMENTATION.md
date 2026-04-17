# 质押(Staking)和赎回(Redeem)功能实现

## 概述

在节点参与选举时增加了质押(POS)功能，允许节点质押代币以参与选举，并在锁定期后赎回质押的代币。

## 功能特性

### 1. 质押功能 (Staking)

- **触发时机**: 节点发送JoinElect交易参与选举时
- **质押单位**: 最小单位为 `8 * 10^8` 币（8 SETH），可以是多个倍数
- **质押目标**: 质押的币放入当前pool index对应的固定地址
- **配置参数**: 通过配置文件中的 `stake_units` 参数控制质押数量
- **追加质押**: 支持多次质押，每次追加质押会累加到总质押金额
- **锁定期重置**: 每次追加质押都会将锁定期重置为新的1008个epoch
- **FTS计算**: 使用当前总质押金额计算FTS权重

#### 配置示例
```ini
[seth]
stake_units = 1  # 质押1个单位 (8 * 10^8 币 = 8 SETH)
# stake_units = 5  # 质押5个单位 (5 * 8 * 10^8 币 = 40 SETH)
```

### 2. 赎回功能 (Redeem)

- **锁定期**: 1008个epoch后允许赎回（7天 * 24小时 * 6个epoch/小时）
- **锁定期计算**: 从最后一次质押（包括追加质押）开始计算
- **赎回金额**: 赎回时返还全部累计质押金额
- **赎回流程**: 发送kRedeemStake交易，从pool地址赎回质押的币
- **验证机制**: 
  - 检查是否已过锁定期（从最后一次质押开始）
  - 验证pool地址余额是否充足
  - 确认质押信息存在

## 实现细节

### 1. Protobuf定义修改

#### bls.proto
```protobuf
message JoinElectInfo {
    optional uint32 shard_id = 1;
    optional uint32 member_idx = 2;
    optional uint32 change_idx = 3;
    optional VerifyVecBrdReq g2_req = 4;
    optional bytes addr = 5;
    optional uint64 stoke = 6;
    optional bytes public_key = 7;
    optional uint64 stake_amount = 8;  // 本次质押金额
    optional uint64 stake_elect_height = 9;  // 质押时的选举高度（每次追加质押时更新）
    optional uint64 total_staked = 10;  // 总质押金额（累计所有质押）
}
```

#### pools.proto
```protobuf
enum StepType {
    // ... 其他类型 ...
    kJoinElect = 13;  // 参与选举交易
    kRedeemStake = 19;  // 赎回质押交易
}
```

### 2. 核心文件修改

#### src/init/network_init.cc
- **函数**: `SendJoinElectTransaction()`
- **修改内容**:
  - 从配置文件读取 `stake_units` 参数
  - 计算质押金额 = `stake_units * 256 * 10^8`
  - 验证账户余额是否充足
  - 设置 `join_info.stake_amount` 和 `join_info.stake_elect_height`

#### src/consensus/zbft/join_elect_tx_item.cc
- **函数**: `HandleTx()`
- **修改内容**:
  - 验证质押金额是否为最小单位的倍数
  - 检查账户余额是否足够支付质押金额和gas费用
  - 计算pool地址: `common::GetPoolAddress(pool_index)`
  - **检查是否存在旧的质押记录**（支持追加质押）
  - 从发送者账户扣除本次质押金额
  - 将质押金额转入pool地址
  - **累加总质押金额**: `total_staked = existing_stake + stake_amount`
  - **重置锁定期**: 使用当前elect_height作为新的锁定期起点
  - 保存更新后的质押信息: `prefix_db_->SaveStakeInfo(total_staked, new_elect_height, ...)`
  - 设置`join_info.total_staked`用于FTS计算

#### src/consensus/zbft/redeem_stake_tx_item.cc (新文件)
- **类**: `RedeemStakeTxItem`
- **功能**:
  - 处理赎回质押交易
  - 验证锁定期是否已过 (1008 epochs，从最后一次质押开始计算)
  - **从pool地址转回全部累计质押金额**到用户账户
  - 删除质押信息记录
  - 处理赎回质押交易
  - 验证锁定期是否已过 (4320 epochs)
  - 从pool地址转回质押金额到用户账户
  - 删除质押信息记录

### 3. 数据库接口 (需要实现)

需要在 `prefix_db` 中实现以下接口:

```cpp
// 保存质押信息（支持追加质押）
// total_stake_amount: 累计总质押金额
// stake_elect_height: 最新的质押选举高度（每次追加时更新）
bool SaveStakeInfo(
    const std::string& address,
    uint64_t total_stake_amount,
    uint64_t stake_elect_height,
    uint32_t pool_index,
    uint64_t stake_block_height);

// 获取质押信息
// 返回的stake_amount是累计总质押金额
bool GetStakeInfo(
    const std::string& address,
    uint64_t* total_stake_amount,
    uint64_t* stake_elect_height,
    uint32_t* pool_index,
    uint64_t* stake_block_height);

// 删除质押信息
bool RemoveStakeInfo(const std::string& address);
```

### 4. 工具函数 (需要实现)

需要在 `common` 命名空间中实现:

```cpp
// 根据pool index获取pool地址
std::string GetPoolAddress(uint32_t pool_index);

// 从地址获取pool index
uint32_t GetAddressPoolIndex(const std::string& address);
```

## 使用流程

### 质押流程

1. **配置质押数量**
   ```ini
   [seth]
   stake_units = 2  # 质押2个单位 (16 SETH)
   ```

2. **启动节点**
   - 节点启动后会自动发送JoinElect交易
   - 交易中包含质押金额信息

3. **共识处理**
   - Leader收到交易后验证质押金额
   - 检查是否存在旧的质押记录
   - 如果存在，累加到总质押金额
   - 从发送者账户扣除本次质押金额
   - 将质押金额转入pool地址
   - 更新质押信息（总金额、新的锁定期起点）
   - 记录total_staked用于FTS计算

4. **追加质押**
   - 可以多次发送JoinElect交易追加质押
   - 每次追加都会重置锁定期为新的1008个epoch
   - 总质押金额累加，用于FTS权重计算

### 赎回流程

1. **等待锁定期**
   - 必须等待1008个epoch后才能赎回（约7天）
   - 锁定期从最后一次质押（包括追加质押）开始计算

2. **发送赎回交易**
   ```cpp
   // 创建赎回交易
   auto tx = CreateTransaction();
   tx->set_step(pools::protobuf::kRedeemStake);
   // ... 设置其他参数 ...
   ```

3. **共识处理**
   - 验证锁定期是否已过（1008个epoch）
   - 从pool地址转回全部累计质押金额
   - 删除质押信息记录

## 安全考虑

1. **金额验证**: 质押金额必须是 `8 * 10^8` 的倍数（8 SETH的倍数）
2. **余额检查**: 确保账户有足够余额支付质押金额和gas费用
3. **锁定期验证**: 严格检查1008个epoch的锁定期（约7天），从最后一次质押开始计算
4. **Pool余额验证**: 赎回时检查pool地址是否有足够余额（全部累计质押金额）
5. **重复赎回防护**: 赎回成功后立即删除质押信息记录
6. **追加质押保护**: 每次追加质押都会重置锁定期，防止绕过锁定期限制

## 常量定义

```cpp
// 最小质押单位: 8 * 10^8 币 (8 SETH)
static const uint64_t kMinStakeUnit = 8 * 100000000llu;

// 锁定期: 7天 * 24小时 * 6个epoch/小时 = 1008个epoch
static const uint64_t kStakeLockEpochs = 7 * 24 * 6;
```

## 待完成工作

1. **数据库接口实现**
   - 在 `protos/prefix_db.h` 和 `protos/prefix_db.cc` 中实现质押信息的存储接口

2. **工具函数实现**
   - 在 `common/utils.h` 和 `common/utils.cc` 中实现pool地址相关函数

3. **交易路由注册**
   - 在交易处理器中注册 `kRedeemStake` 交易类型

4. **编译protobuf**
   - 重新编译protobuf文件生成新的C++代码

5. **测试**
   - 单元测试: 测试质押和赎回逻辑
   - 集成测试: 测试完整的质押-锁定-赎回流程
   - 边界测试: 测试各种异常情况

## 日志示例

### 质押成功日志
```
[INFO] Staking 25600000000 coins (1 units) for election, elect_height: 12345
[INFO] Staked 25600000000 coins to pool 5 address 0x1234..., elect_height: 12345
```

### 赎回成功日志
```
[INFO] Redeemed 25600000000 coins from pool 5 address 0x1234... to 0x5678..., 
       epochs passed: 1008, stake_elect_height: 12345, current_elect_height: 13353
```

### 质押成功日志
```
[INFO] Initial stake: 800000000 coins (8 SETH) to pool 5 address 0x1234..., elect_height: 12345
[INFO] Additional stake: added 800000000 coins (total now: 1600000000 = 16 SETH) to pool 5 address 0x1234..., 
       lock period reset to elect_height: 12500 (previous: 12345)
```

### 赎回成功日志
```
[INFO] Redeemed total 1600000000 coins (16 SETH) from pool 5 address 0x1234... to 0x5678..., 
       epochs passed: 1008, stake_elect_height: 12500, current_elect_height: 13508
```

### 错误日志
```
[ERROR] Invalid stake amount: 500000000, must be multiple of 800000000 (8 SETH)
[ERROR] Insufficient balance for stake: have 500000000, need 800000000 + gas
[ERROR] Stake lock period not passed: 500/1008 epochs
[ERROR] No stake info found for address: 0x5678...
```

## 配置文件示例

```ini
[seth]
# 私钥
prikey = your_private_key_here

# 网络配置
net_id = 3

# 质押配置
stake_units = 1  # 质押1个单位 (8 * 10^8 币 = 8 SETH)
# 如果不配置或设为0，则不质押

# 其他配置...
```

## API接口 (可选)

可以添加HTTP API接口查询质押信息:

```
GET /stake_info?address=0x1234...
Response:
{
  "address": "0x1234...",
  "total_stake_amount": "1600000000",
  "total_stake_seth": "16",
  "stake_elect_height": 12500,
  "pool_index": 5,
  "stake_block_height": 67890,
  "current_elect_height": 13000,
  "epochs_passed": 500,
  "can_redeem": false,
  "epochs_remaining": 508,
  "lock_period_epochs": 1008
}
```

## 总结

本实现为Seth区块链添加了完整的质押和赎回功能，支持:
- ✅ 灵活的质押金额配置 (8 SETH的倍数)
- ✅ 自动将质押金额转入pool地址
- ✅ **支持追加质押，累计总质押金额**
- ✅ **每次追加质押重置锁定期为新的1008个epoch**
- ✅ **FTS计算使用总质押金额（total_staked）**
- ✅ 1008个epoch的锁定期保护（约7天）
- ✅ 安全的赎回机制（赎回全部累计质押金额）
- ✅ 完整的错误处理和日志记录

该功能为节点参与选举提供了经济激励机制，增强了网络的安全性和去中心化程度。
