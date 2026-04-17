# Staking Quick Start Guide

## 概述

质押功能允许节点通过锁定代币来参与选举，提高被选为领导者的概率。

## 关键参数

- **最小质押单位**: 8 SETH (8 * 10^8 coins)
- **锁定期**: 604,800 秒 (1008 * 600 秒 = 7天)
- **锁定期计算**: 使用区块时间戳 (current_timestamp - stake_timestamp)
- **追加质押**: 支持，每次追加会重置锁定期
- **FTS计算**: 使用累计质押总额

## 配置

### 1. 编辑配置文件 (seth.conf)

```ini
[seth]
# 质押单位数量 (每单位 = 8 SETH)
# 例如: stake_units = 1 表示质押 8 SETH
#      stake_units = 2 表示质押 16 SETH
stake_units = 1
```

### 2. 确保账户余额充足

质押前确保账户余额 >= 质押金额 + gas费用

例如，质押 1 单位 (8 SETH):
- 需要余额: 8 * 10^8 + gas费用

## 使用流程

### 初次质押

1. **配置质押单位**
   ```ini
   stake_units = 1  # 质押 8 SETH
   ```

2. **启动节点**
   ```bash
   ./seth --config seth.conf
   ```

3. **节点自动质押**
   - 节点加入选举时自动发送质押交易
   - 查看日志确认:
   ```
   Staking 800000000 coins (1 units) for election, elect_height: XXX
   Initial stake: 800000000 coins to pool X address YYY, elect_height: XXX
   ```

### 追加质押

1. **再次发送加入选举交易**
   - 使用相同配置或修改 `stake_units`
   - 节点会检测到已有质押

2. **系统自动处理**
   - 累加质押金额
   - 重置锁定期为新的 1008 epoch
   - 查看日志确认:
   ```
   Additional stake: added 800000000 coins (total now: 1600000000) to pool X,
   lock period reset to elect_height: YYY (previous: XXX)
   ```

### 赎回质押

1. **等待锁定期结束**
   - 从最后一次质押的区块时间戳开始计算
   - 锁定期: 604,800 秒 (7天)
   - 判断条件: 当前区块时间戳 - 质押区块时间戳 >= 604,800 秒

2. **发送赎回交易**
   ```bash
   # 通过 RPC 或命令行发送 kRedeemStake 交易
   # 交易类型: pools::protobuf::kRedeemStake (19)
   ```

3. **系统处理赎回**
   - 验证锁定期已过
   - 从池地址转回全部累计质押金额
   - 删除质押信息
   - 查看日志确认:
   ```
   Redeemed total 1600000000 coins from pool X address YYY to ZZZ,
   epochs passed: 1008, stake_elect_height: XXX, current_elect_height: YYY
   ```

## 常见场景

### 场景 1: 单次质押 8 SETH

```ini
stake_units = 1
```

- 质押金额: 8 * 10^8 coins
- 锁定期: 1008 epochs
- 赎回金额: 8 * 10^8 coins

### 场景 2: 单次质押 16 SETH

```ini
stake_units = 2
```

- 质押金额: 16 * 10^8 coins
- 锁定期: 1008 epochs
- 赎回金额: 16 * 10^8 coins

### 场景 3: 追加质押

**第一次质押:**
```ini
stake_units = 1  # 8 SETH
```
- 总质押: 8 * 10^8
- 质押时间戳: 1704067200 (2024-01-01 00:00:00)
- 质押区块高度: 1000

**第二次质押 (4天后):**
```ini
stake_units = 1  # 再质押 8 SETH
```
- 总质押: 16 * 10^8
- 质押时间戳重置: 1704412800 (2024-01-05 00:00:00)
- 质押区块高度: 1500
- 锁定期重置: 从 2024-01-05 开始计算 7天

**赎回 (第二次质押后 7天):**
- 赎回时间: 2024-01-12 00:00:00 (timestamp: 1705017600)
- 经过时间: 1705017600 - 1704412800 = 604,800 秒 ✅
- 赎回金额: 16 * 10^8 (全部累计金额)

## 错误处理

### 错误 1: 质押金额无效

```
Invalid stake amount: XXX, must be multiple of 800000000
```

**原因**: 质押金额不是 8 * 10^8 的倍数

**解决**: 确保 `stake_units` 是正整数

### 错误 2: 余额不足

```
Insufficient balance for staking: have XXX, need YYY
```

**原因**: 账户余额不足以支付质押金额和 gas

**解决**: 充值账户或减少 `stake_units`

### 错误 3: 锁定期未到

```
Stake lock period not passed: XXX/604800 seconds (Y days)
```

**原因**: 尝试在锁定期结束前赎回 (距离质押时间不足 7天)

**解决**: 等待锁定期结束 (604,800 秒 = 7天)

### 错误 4: 无质押信息

```
No stake info found for address: XXX
```

**原因**: 该地址没有质押记录

**解决**: 先进行质押操作

## 监控和查询

### 查看质押状态

```bash
# 查看日志
tail -f seth.log | grep -i stake

# 查看数据库 (需要数据库工具)
# Key: kStakeInfoPrefix + address
# Value: total_stake(8) + elect_height(8) + pool_index(4) + block_height(8)
```

### 计算可赎回时间

```
可赎回时间 = 质押区块时间戳 + 604,800 秒
当前区块时间戳 >= 可赎回时间 时可以赎回

示例:
质押时间: 2024-01-01 00:00:00 (timestamp: 1704067200)
可赎回时间: 2024-01-08 00:00:00 (timestamp: 1704672000)
锁定期: 604,800 秒 = 7 天
```

### 查看池余额

```bash
# 通过 RPC 查询池地址余额
# 池地址 = GetPoolAddress(pool_index)
# pool_index = GetAddressPoolIndex(user_address)
```

## 最佳实践

### 1. 质押前检查

- ✅ 确认账户余额充足
- ✅ 理解锁定期限制 (1008 epochs ≈ 7天)
- ✅ 确认 `stake_units` 配置正确

### 2. 追加质押注意事项

- ⚠️ 每次追加会重置锁定期
- ⚠️ 锁定期从最后一次质押的区块时间戳开始计算
- ⚠️ 需要等待 604,800 秒 (7天) 才能赎回
- ⚠️ 赎回时返回全部累计金额

### 3. 赎回前确认

- ✅ 确认锁定期已过 (距离质押时间 >= 604,800 秒)
- ✅ 确认池地址有足够余额
- ✅ 准备足够 gas 费用

### 4. 安全建议

- 🔒 不要质押全部余额 (保留 gas 费用)
- 🔒 记录质押时间和金额
- 🔒 定期检查质押状态
- 🔒 备份私钥和配置文件

## 技术细节

### 质押流程

```
用户 → 配置 stake_units
     ↓
节点 → SendJoinElectTransaction()
     ↓
共识 → JoinElectTxItem::HandleTx()
     ↓
     ├─ 验证金额 (8 * 10^8 的倍数)
     ├─ 检查余额
     ├─ 转账到池地址
     ├─ 保存质押信息
     └─ 更新 total_staked (用于 FTS)
```

### 赎回流程

```
用户 → 发送 kRedeemStake 交易
     ↓
共识 → RedeemStakeTxItem::HandleTx()
     ↓
     ├─ 获取质押信息 (stake_block_height)
     ├─ 获取质押区块时间戳 (stake_timestamp)
     ├─ 获取当前区块时间戳 (current_timestamp)
     ├─ 验证锁定期 (current_timestamp - stake_timestamp >= 604,800)
     ├─ 从池地址转回全部金额
     ├─ 删除质押信息
     └─ 扣除 gas 费用
```

### 数据库存储

```
Key: "ak\x01" + address
Value: [28 bytes]
  - total_stake_amount: 8 bytes (uint64_t)
  - stake_elect_height: 8 bytes (uint64_t)
  - pool_index: 4 bytes (uint32_t)
  - stake_block_height: 8 bytes (uint64_t)
```

## FAQ

**Q: 可以部分赎回吗？**
A: 不可以，赎回时会返回全部累计质押金额。

**Q: 追加质押会影响之前的质押吗？**
A: 会重置锁定期，需要从最后一次质押的区块时间戳开始等待 604,800 秒 (7天)。

**Q: 质押的币在哪里？**
A: 在池地址中，池地址由 pool_index 确定性生成。

**Q: 锁定期可以缩短吗？**
A: 不可以，锁定期固定为 604,800 秒 (7天)。

**Q: 质押会影响 FTS 吗？**
A: 会，FTS 计算使用 total_staked，质押越多被选为领导者的概率越高。

**Q: 节点重启后质押信息会丢失吗？**
A: 不会，质押信息保存在数据库中，重启后自动恢复。

## 相关文档

- `STAKING_IMPLEMENTATION.md` - 实现设计文档
- `ADDITIONAL_STAKING_FEATURE.md` - 追加质押功能详解
- `STAKING_IMPLEMENTATION_COMPLETE.md` - 完整实现总结
- `STAKING_TIMESTAMP_UPDATE.md` - 时间戳计算方式更新说明

## 支持

如有问题，请查看日志文件或联系技术支持。
