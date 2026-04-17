# 质押锁定期计算方式更新

## 变更说明

### 原方案
- 使用 **elect_height** (选举高度) 计算锁定期
- 判断条件: `current_elect_height - stake_elect_height >= 1008 epochs`

### 新方案 ✅
- 使用 **block timestamp** (区块时间戳) 计算锁定期
- 判断条件: `current_timestamp - stake_timestamp >= 1008 * 600 秒`

## 技术细节

### 锁定期计算

```cpp
// 锁定期: 1008 * 600 秒 = 604,800 秒 = 7 天
static const uint64_t kStakeLockSeconds = 1008 * 600;

// 获取质押时的区块时间戳
view_block::protobuf::ViewBlockItem stake_view_block;
prefix_db_->GetBlockWithHeight(network_id, pool_index, stake_block_height, &stake_view_block);
uint64_t stake_timestamp = stake_view_block.block_info().timestamp();

// 获取当前区块时间戳
uint64_t current_timestamp = view_block.block_info().timestamp();

// 计算经过的时间
uint64_t seconds_passed = current_timestamp - stake_timestamp;

// 判断是否可以赎回
if (seconds_passed >= kStakeLockSeconds) {
    // 可以赎回
}
```

### 数据库存储

质押信息中保存 `stake_block_height`，用于查询质押时的区块时间戳：

```
Key: "ak\x01" + address
Value: [28 bytes]
  - total_stake_amount: 8 bytes (uint64_t)
  - stake_elect_height: 8 bytes (uint64_t) [保留字段，暂未使用]
  - pool_index: 4 bytes (uint32_t)
  - stake_block_height: 8 bytes (uint64_t) [用于查询时间戳]
```

## 优势

### 1. 更精确的时间控制
- 基于实际时间而非区块高度
- 不受出块速度波动影响
- 锁定期更可预测

### 2. 更符合用户预期
- 用户理解 "7天" 比 "1008个epoch" 更直观
- 时间戳是绝对时间，不会因网络状态改变

### 3. 更灵活的实现
- 可以轻松调整锁定期（修改秒数即可）
- 不依赖于 elect_height 的更新频率

## 实现变更

### 修改的文件

**src/consensus/zbft/redeem_stake_tx_item.cc**

#### 变更 1: 锁定期常量
```cpp
// 旧代码
static const uint64_t kStakeLockEpochs = 7 * 24 * 6;

// 新代码
static const uint64_t kStakeLockSeconds = 1008 * 600;
```

#### 变更 2: 获取质押时间戳
```cpp
// 新增代码
view_block::protobuf::ViewBlockItem stake_view_block;
if (!prefix_db_->GetBlockWithHeight(
        view_block.qc().network_id(),
        view_block.qc().pool_index(),
        stake_block_height,
        &stake_view_block)) {
    block_tx.set_status(consensus::kConsensusError);
    SETH_ERROR("Failed to get stake block at height: %lu", stake_block_height);
    break;
}
uint64_t stake_timestamp = stake_view_block.block_info().timestamp();
```

#### 变更 3: 时间戳比较
```cpp
// 旧代码
elect::protobuf::ElectBlock current_elect_block;
prefix_db_->GetLatestElectBlock(network_id, &current_elect_block);
uint64_t epochs_passed = current_elect_block.elect_height() - stake_elect_height;
if (epochs_passed < kStakeLockEpochs) { ... }

// 新代码
uint64_t current_timestamp = view_block.block_info().timestamp();
uint64_t seconds_passed = current_timestamp - stake_timestamp;
if (seconds_passed < kStakeLockSeconds) {
    SETH_ERROR("Stake lock period not passed: %lu/%lu seconds (%lu days)",
        seconds_passed, kStakeLockSeconds, seconds_passed / 86400);
    break;
}
```

#### 变更 4: 日志输出
```cpp
// 旧代码
SETH_INFO("Redeemed total %lu coins, epochs passed: %lu, 
    stake_elect_height: %lu, current_elect_height: %lu", ...);

// 新代码
SETH_INFO("Redeemed total %lu coins, seconds passed: %lu, 
    stake_timestamp: %lu, current_timestamp: %lu, 
    stake_block_height: %lu, redeem_block_height: %lu", ...);
```

## 使用示例

### 场景 1: 正常赎回

```
质押时间: 2024-01-01 00:00:00 (timestamp: 1704067200)
质押区块高度: 1000
锁定期: 604,800 秒 (7天)

赎回时间: 2024-01-08 00:00:00 (timestamp: 1704672000)
赎回区块高度: 2000
经过时间: 604,800 秒

判断: 604,800 >= 604,800 ✅ 可以赎回
```

### 场景 2: 锁定期未到

```
质押时间: 2024-01-01 00:00:00 (timestamp: 1704067200)
质押区块高度: 1000
锁定期: 604,800 秒 (7天)

赎回时间: 2024-01-05 00:00:00 (timestamp: 1704412800)
赎回区块高度: 1500
经过时间: 345,600 秒 (4天)

判断: 345,600 < 604,800 ❌ 不能赎回
错误: "Stake lock period not passed: 345600/604800 seconds (4 days)"
```

### 场景 3: 追加质押后赎回

```
第一次质押:
  时间: 2024-01-01 00:00:00 (timestamp: 1704067200)
  区块高度: 1000
  金额: 8 SETH

第二次质押 (追加):
  时间: 2024-01-05 00:00:00 (timestamp: 1704412800)
  区块高度: 1500
  金额: 8 SETH
  总金额: 16 SETH
  锁定期重置: 从 1704412800 开始计算

赎回时间: 2024-01-12 00:00:00 (timestamp: 1705017600)
经过时间: 1705017600 - 1704412800 = 604,800 秒

判断: 604,800 >= 604,800 ✅ 可以赎回
赎回金额: 16 SETH (全部累计金额)
```

## 时间计算参考

```
1 epoch = 600 秒 = 10 分钟
1008 epochs = 604,800 秒 = 10,080 分钟 = 168 小时 = 7 天

锁定期 = 1008 * 600 = 604,800 秒
       = 604,800 / 60 = 10,080 分钟
       = 10,080 / 60 = 168 小时
       = 168 / 24 = 7 天
```

## 错误处理

### 错误 1: 无法获取质押区块

```
错误信息: "Failed to get stake block at height: XXX"
原因: 数据库中找不到指定高度的区块
解决: 确保区块数据完整，可能需要同步区块数据
```

### 错误 2: 锁定期未到

```
错误信息: "Stake lock period not passed: XXX/604800 seconds (Y days)"
原因: 当前时间距离质押时间不足 7 天
解决: 等待足够时间后再尝试赎回
```

## 测试要点

### 1. 时间戳获取测试
- ✅ 验证能正确获取质押区块的时间戳
- ✅ 验证能正确获取当前区块的时间戳
- ✅ 验证时间戳计算正确

### 2. 锁定期判断测试
- ✅ 测试刚好 604,800 秒时可以赎回
- ✅ 测试少于 604,800 秒时不能赎回
- ✅ 测试超过 604,800 秒时可以赎回

### 3. 追加质押测试
- ✅ 验证追加质押后锁定期重置
- ✅ 验证使用最新的 stake_block_height
- ✅ 验证时间戳从最新质押开始计算

### 4. 边界条件测试
- ✅ 测试时间戳相等的情况
- ✅ 测试时间戳回退的情况（理论上不应发生）
- ✅ 测试区块不存在的情况

## 兼容性说明

### 数据库兼容性
- ✅ 数据库结构未变更
- ✅ `stake_block_height` 字段已存在
- ✅ 无需数据迁移

### 代码兼容性
- ✅ 只修改了赎回逻辑
- ✅ 质押逻辑保持不变
- ✅ 其他模块无影响

## 性能影响

### 额外开销
- 每次赎回需要额外查询一次区块数据
- 查询开销: O(1) - 通过高度索引直接查询
- 影响: 可忽略不计

### 优化建议
- 区块数据已在数据库中，查询速度快
- 可以考虑缓存最近的区块数据（可选）

## 总结

### 变更内容
- ✅ 从 elect_height 改为 block timestamp
- ✅ 锁定期从 1008 epochs 改为 604,800 秒
- ✅ 更精确、更直观的时间控制

### 优势
- ✅ 基于实际时间，更可预测
- ✅ 不受出块速度影响
- ✅ 用户体验更好

### 影响
- ✅ 只修改赎回逻辑
- ✅ 无需数据迁移
- ✅ 性能影响可忽略

变更已完成，代码已通过编译检查！🎉
