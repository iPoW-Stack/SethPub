# Same-Shard Atomicity 快速参考

## 🎯 核心规则

```
同一账户创建多个合约 
    ↓
它们会被部署到该账户所在的分片
    ↓
合约调用在同一交易池中原子执行
    ↓
要么全成功，要么全失败（自动回滚）
```

## 📋 检查清单

部署 AMM 合约时：

- [ ] 所有 3 个合约都由 **同一账户** 创建？
- [ ] `from` 字段都是 `MY_ACCOUNT`？
- [ ] 先部署 `AMMPool`，再部署其他合约？
- [ ] 部署后调用了 `setTreasury()` 和 `setRouter()`？
- [ ] 没有混用不同账户？

## 🔄 调用链

正确的原子链：
```
用户调用 Router.atomicSwap()
    ↓
Router 调用 Treasury.executeSwap()
    ↓
Treasury 调用 Pool.swapXtoY()
    ↓
Pool 执行 require(滑点检查)
    ↓
如果 require 失败 → 整个交易回滚
```

## ⚙️ 合约关键代码片段

### Pool 合约

```solidity
contract AMMPool {
    address public treasury;
    
    function swapXtoY(uint256 amountXIn, uint256 minYOut) 
        external 
        returns (uint256 amountYOut, uint256 swapId) 
    {
        // 关键：只允许 Treasury 调用
        require(msg.sender == treasury, "Only Treasury");
        
        // 计算输出
        uint256 amountYOut = calculateOutput(amountXIn);
        
        // 关键：require 失败导致回滚
        require(amountYOut >= minYOut, "Slippage exceeded");
        
        // 更新状态（原子）
        reserveTokenX += amountXIn;
        reserveTokenY -= amountYOut;
        
        return (amountYOut, swapId);
    }
}
```

### Treasury 合约

```solidity
contract AMMTreasury {
    address public pool;
    address public router;
    mapping(address => uint256) public balanceX;
    
    function executeSwap(
        address user,
        uint256 amountXIn,
        uint256 minYOut
    ) external returns (uint256 amountYOut) {
        // 关键：只允许 Router 调用
        require(msg.sender == router, "Only Router");
        
        // 检查用户余额
        require(balanceX[user] >= amountXIn, "Insufficient balance");
        
        // 关键：调用同分片 Pool
        (uint256 amountYOut, ) = IAMMPool(pool).swapXtoY(
            amountXIn, 
            minYOut
        );
        
        // 只有当 swapXtoY 成功时才执行
        balanceX[user] -= amountXIn;
        balanceY[user] += amountYOut;
        
        return amountYOut;
    }
}
```

### Router 合约

```solidity
contract AMMRouter {
    address public treasury;
    
    function atomicSwap(
        uint256 amountXIn,
        uint256 minYOut
    ) external returns (uint256 amountYOut) {
        // 直接调用 Treasury
        amountYOut = IAMMTreasury(treasury).executeSwap(
            msg.sender, 
            amountXIn, 
            minYOut
        );
        return amountYOut;
    }
}
```

## 🚀 部署步骤

```python
# 1. 部署 Pool
pool = w3.seth.contract(...).deploy({
    'from': MY_ACCOUNT,  # 关键
    'args': [10000, 10000]
}, KEY)

# 2. 部署 Treasury
treasury = w3.seth.contract(...).deploy({
    'from': MY_ACCOUNT,  # 关键：同账户
    'args': [pool.address]
}, KEY)

# 3. 部署 Router
router = w3.seth.contract(...).deploy({
    'from': MY_ACCOUNT,  # 关键：同账户
    'args': [treasury.address, pool.address]
}, KEY)

# 4. 初始化关系
pool.functions.setTreasury(treasury.address).transact(KEY)
treasury.functions.setRouter(router.address).transact(KEY)
```

## 🧪 验证原子性

### 成功情况

```python
receipt = router.functions.atomicSwap(100, 90).transact(KEY)

assert receipt.get('status') == 0
assert user_balance_after == user_balance_before - 100 + output
assert pool.reserveX == pool_before.reserveX + 100
print("✅ 原子交换成功")
```

### 失败回滚

```python
balance_before = treasury.functions.getUserBalance(user).call()
pool_before = pool.functions.getPoolStats().call()

try:
    receipt = router.functions.atomicSwap(100, 5000).transact(KEY)
except:
    pass

balance_after = treasury.functions.getUserBalance(user).call()
pool_after = pool.functions.getPoolStats().call()

assert balance_after == balance_before, "余额已回滚"
assert pool_after[0] == pool_before[0], "Pool 已回滚"
print("✅ 自动回滚验证成功")
```

## 📊 对比表

| 方面 | 同分片 | 跨分片 |
|------|-------|-------|
| 部署 | 同账户 | 不同账户 |
| 原子性 | ✅ 自动 | ❌ 无 |
| 回滚 | ✅ 自动 | ❌ 手动 |
| 链式调用 | ✅ 支持 | ❌ 异步 |
| 最终化 | 1 块 | 多块 |
| 补偿 | 无需 | 必须 |
| 代码行数 | 200 | 400+ |

## ⚠️ 常见错误

### ❌ 错误 1：不同账户

```python
# 错误
pool = deploy(AMMPool, from=account_a)
treasury = deploy(AMMTreasury, from=account_b)  # 不同账户！
# 结果：不同分片，无法原子调用
```

### ❌ 错误 2：忘记初始化

```python
# 错误
pool = deploy(AMMPool)
treasury = deploy(AMMTreasury, pool.address)
# 忘记调用 setTreasury()
# 结果：Treasury 未关联到 Pool
```

### ❌ 错误 3：用 if 而非 require

```solidity
// 错误
if (amountYOut < minYOut) {
    return 0;  // 不回滚
}
// 结果：部分状态被修改

// 正确
require(amountYOut >= minYOut, "Slippage");  // 全部回滚
```

## 📈 性能指标

```
同分片原子交换（成功）:
  时间：≈ 3 秒（1 个块）
  Gas：≈ 100k（基础执行）
  最终化：立即

同分片原子交换（失败回滚）:
  时间：≈ 3 秒（1 个块）
  Gas：≈ 50k（部分执行）
  最终化：立即

跨分片交换（失败后补偿）:
  时间：≈ 15-30 秒（5-10 块）
  Gas：≈ 200k+（执行+补偿）
  最终化：延迟
```

## 🔗 相关文档

- 📄 完整设计：`SAME_SHARD_ATOMICITY_DESIGN.md`
- 🧪 测试代码：`seth3.py` - `test_amm_same_shard_atomic_swap()`
- 📚 学习资源：`SETH_INDEX.md`

## 💡 关键要点

1. **一个规则**：同账户 = 同分片 = 自动原子
2. **三层架构**：Pool → Treasury → Router
3. **四个字段**：`from`, `salt`, `args`, `KEY`
4. **五个步骤**：部署 → 初始化 → 存款 → 交换 → 验证

---

**速查版本**: 1.0  
**最后更新**: 2024-04-17
