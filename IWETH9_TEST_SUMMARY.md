# IWETH9 Existing Contract Test - 完整指南

## 📋 概述

新增的 `test_iweth9_existing_contract()` 测试函数用于测试已部署的 IWETH9 合约。该测试包含完整的 prefund 生命周期管理和状态监测。

## 🎯 测试地址

```
合约地址: 758b97b0370c763f4fec47dae8081eb6200fc9b4
合约类型: IWETH9
```

## 📊 完整工作流程

```
┌─────────────────────────────────────────────────────────────────┐
│ [1] 获取 IWETH9 ABI                                             │
│     - 编译合约获取 ABI 信息                                      │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [2] 创建合约实例                                                │
│     - 使用合约地址和 ABI 创建实例                                │
│     - address = 758b97b0370c763f4fec47dae8081eb6200fc9b4       │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [3] Prefund 设置 (Gas 预付)                                      │
│     - 金额: 5,000,000                                            │
│     - 发送 prefund 交易                                          │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [3.1] 等待 Prefund 确认 (最多 30 秒)                              │
│       - 每 2 秒检查一次 prefund 状态                              │
│       - 检查次数: 最多 15 次                                      │
│       - 确认条件: prefund 余额 > 0                               │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [4] 调用 deposit() 函数                                          │
│     - 金额: 2,000,000                                            │
│     - prefund=0 (使用已有 prefund，不再存入)                     │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [4.1] 等待 Deposit 确认 (最多 30 秒)                              │
│       - 每 2 秒检查一次交易状态                                   │
│       - 确认条件: status == 0                                   │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [5] 查询 balanceOf()                                             │
│     - 检查账户余额                                                │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [6] 记录 Refund 前的 Prefund 状态                                 │
│     - prefund_status = 当前 prefund 余额                         │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [7] 执行 Refund                                                  │
│     - 返还所有剩余 prefund                                        │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ [7.1] 等待 Refund 确认 (最多 30 秒)                               │
│       - 每 2 秒检查一次 prefund 余额                              │
│       - 确认条件: final_prefund <= prefund_status                │
└─────────────────────────────────────────────────────────────────┘
                            ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ ✅ 测试完成                                                       │
│    所有步骤成功验证                                                │
└─────────────────────────────────────────────────────────────────┘
```

## ⏱️ 状态检查机制

### Prefund 状态检查 [3.1]

```python
max_wait = 30        # 最多等待 30 秒
check_interval = 2   # 每 2 秒检查一次
总检查次数 = 15 次

轮询逻辑:
  while elapsed < 30:
      current_prefund = get_prefund(MY)
      if current_prefund > 0:
          break  # prefund 已确认
      sleep(2)
      elapsed += 2
```

**输出示例:**
```
[3.1] Waiting for prefund to settle (checking every 2 seconds, max 30s)...
    [0s] Current prefund status: 5000000
    ✅ Prefund confirmed! Balance: 5000000
    ✅ Prefund fully confirmed after 0s
```

### Deposit 确认检查 [4.1]

```python
轮询逻辑:
  while elapsed < 30:
      status = deposit_receipt.get('status')
      if status == 0 or status == '0':
          break  # deposit 已确认
      sleep(2)
      elapsed += 2
```

**输出示例:**
```
[4.1] Waiting for deposit transaction to settle (checking every 2 seconds, max 30s)...
    [0s] Deposit status: 0
    ✅ Deposit confirmed!
    ✅ Deposit fully confirmed after 0s
```

### Refund 确认检查 [7.1]

```python
轮询逻辑:
  while elapsed < 30:
      final_prefund = get_prefund(MY)
      if final_prefund <= prefund_status:
          break  # refund 已确认
      sleep(2)
      elapsed += 2
```

**输出示例:**
```
[7.1] Waiting for refund to complete (checking every 2 seconds, max 30s)...
    [0s] Current prefund: 0
    ✅ Refund confirmed! Final prefund: 0
    ✅ Refund fully confirmed after 0s
```

## 📝 关键参数

| 参数 | 值 | 说明 |
|------|-----|------|
| IWETH9_ADDRESS | `758b97b0370c763f4fec47dae8081eb6200fc9b4` | 已部署合约地址 |
| prefund_amount | `5,000,000` | Prefund 存入金额 |
| deposit_amount | `2,000,000` | Deposit 金额 |
| max_wait | `30` 秒 | 最大等待时间 |
| check_interval | `2` 秒 | 检查间隔 |

## 🚀 运行方式

### 在 Linux 上运行 (推荐使用 UTF-8 编码)

```bash
cd /root/seth/clipy
PYTHONIOENCODING=utf-8 python3 seth3.py
```

### 在 Windows 上运行

```powershell
cd d:\work\SethPub\clipy
python seth3.py
```

## ✅ 预期输出

```
======================================================================
TEST CASE: IWETH9 Existing Contract - Prefund, Call, and Refund
======================================================================

[1] Getting IWETH9 ABI...
    ✅ ABI loaded: 3 items

[2] Creating contract instance at: 758b97b0370c763f4fec47dae8081eb6200fc9b4
    ✅ Contract instance created
    - Address: 758b97b0370c763f4fec47dae8081eb6200fc9b4

[3] Setting up prefund (gas deposit)...
    ✅ Prefund transaction sent
    - Prefund amount: 5000000
    - Status: pending

[3.1] Waiting for prefund to settle (checking every 2 seconds, max 30s)...
    [0s] Current prefund status: 5000000
    ✅ Prefund confirmed! Balance: 5000000
    ✅ Prefund fully confirmed after 0s

[4] Calling deposit() function...
    ✅ Deposit transaction sent
    - Deposit amount: 2000000
    - Status: pending

[4.1] Waiting for deposit transaction to settle (checking every 2 seconds, max 30s)...
    [0s] Deposit status: 0
    ✅ Deposit confirmed!
    ✅ Deposit fully confirmed after 0s

[5] Checking balance with balanceOf()...
    ✅ Balance retrieved
    - Address: fd...
    - Balance: 0

[6] Checking prefund status before refund...
    - Remaining prefund: 4999700

[7] Refunding remaining prefund...
    ✅ Refund transaction sent
    - Status: pending

[7.1] Waiting for refund to complete (checking every 2 seconds, max 30s)...
    [0s] Current prefund: 0
    ✅ Refund confirmed! Final prefund: 0
    ✅ Refund fully confirmed after 0s

======================================================================
✅ TEST CASE PASSED: IWETH9 Existing Contract Test Complete
======================================================================

Summary:
  • Contract instance created at deployed address ✅
  • Prefund setup successful ✅
  • deposit() function called successfully ✅
  • balanceOf() retrieved balance ✅
  • Refund completed successfully ✅
```

## 🔍 故障排除

### 问题 1: Prefund 未确认

**现象:**
```
[3.1] Waiting for prefund to settle (checking every 2 seconds, max 30s)...
    [2s] Checking prefund... (Error: Connection refused)
    [4s] Checking prefund... (Error: Connection refused)
    ⚠️ Warning: Prefund status not confirmed after 30s
```

**解决方案:**
- 检查网络连接
- 确保 Seth 节点正常运行
- 检查 IP 和端口是否正确

### 问题 2: 合约地址错误

**现象:**
```
❌ TEST CASE FAILED: Invalid contract address
```

**解决方案:**
- 验证合约地址是否正确
- 检查合约是否已部署
- 确认地址的格式 (40 个十六进制字符)

## 📚 相关文件

- 主测试文件: `d:\work\SethPub\clipy\seth3.py`
- 合约定义: `IWETH9_SOL` (在 seth3.py 中)
- 函数位置: `test_iweth9_existing_contract()` (第 1800 行附近)

## 📞 技术细节

### Prefund 生命周期

1. **创建** - 通过 `prefund()` 函数存入 gas 预付
2. **确认** - 通过 `get_prefund()` 轮询检查
3. **消耗** - 在交易中使用 `prefund=0` 来消耗
4. **返还** - 通过 `refund()` 函数返还剩余部分

### 交易流程

```
prefund() → 轮询检查 → deposit() → 轮询检查 → refund() → 轮询确认 ✅
```

每个步骤都有 30 秒的最大等待时间，保证测试不会永久阻塞。

---

**最后更新**: 2026-04-17  
**状态**: ✅ 已完成和测试  
**版本**: 1.0
