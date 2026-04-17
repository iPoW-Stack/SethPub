# Seth 跨分片 AMM 测试 - 使用指南

## 📖 文档导航

根据你的需求选择适合的文档：

### 🚀 快速入门 (5 分钟)
→ **`AMM_QUICK_REFERENCE.md`**
- 核心概念速览
- 关键数据和时间复杂度
- 代码片段示例
- 快速参考表

### 🎓 学习测试设计 (20 分钟)
→ **`AMM_CROSS_SHARD_TEST_DESIGN.md`**
- 完整的问题描述和论文背景
- 四个测试场景的详细分析
- 状态转移图
- 验证矩阵

### 💼 实战编码指南 (30 分钟)
→ **`CROSS_SHARD_DESIGN_GUIDE.md`**
- 三个设计模式详解
- 分步实现指南
- 性能优化建议
- 安全防护措施
- 完整案例研究

### 📊 完整实现总结 (15 分钟)
→ **`SETH_IMPLEMENTATION_SUMMARY.md`**
- 所有文件的概览
- 核心验证指标
- 问题排查 FAQ
- 改进建议优先级

### 💻 实际代码
→ **`seth3.py`**
- `AMM_POOL_SOL` - 池合约
- `AMM_ROUTER_SOL` - 路由合约
- `test_amm_cross_shard_swap()` - 测试函数
- 4 个核心场景的完整实现

---

## 🎯 根据角色选择

### 👨‍💼 项目经理
**目标**: 理解问题的严重性和影响

1. 阅读: `AMM_QUICK_REFERENCE.md` → 数据表格部分
2. 看: 开发者负担表 (200+ 行代码 vs 10 行)
3. 关键数据: 最终化延迟 5-10 倍

**行动**: 
- 优先排期补偿库的开发
- 考虑协议级改进

---

### 👨‍💻 智能合约开发者
**目标**: 学习如何在无回滚协议上编写正确的合约

**推荐路线**:
```
第 1 步 (5 min):  AMM_QUICK_REFERENCE.md
    → 理解核心问题
    
第 2 步 (20 min): AMM_CROSS_SHARD_TEST_DESIGN.md
    → 理解 4 个场景为什么会发生
    
第 3 步 (30 min): CROSS_SHARD_DESIGN_GUIDE.md
    → 学习 3 个模式如何防护
    
第 4 步 (30 min): seth3.py
    → 学习实际代码实现
    
第 5 步 (20 min): 编写你自己的补偿逻辑
```

**实际练习**:
```python
# 1. 修改测试中的滑点参数
minYOut_1 = 50   # 第一个应该成功
minYOut_2 = 5000 # 第二个应该失败

# 2. 观察 SwapFailed 事件
# 3. 实现补偿逻辑
# 4. 验证补偿被正确处理
```

---

### 🔬 研究员/学者
**目标**: 验证论文的观点

**推荐路线**:
```
第 1 步: AMM_CROSS_SHARD_TEST_DESIGN.md → 论文背景部分
    阅读原始问题陈述
    
第 2 步: SETH_IMPLEMENTATION_SUMMARY.md → 表格部分
    查看具体的验证矩阵
    
第 3 步: 运行测试
    python seth3.py
    观察具体的事件输出
    
第 4 步: 分析数据
    开发者负担度量
    时间复杂度分析
```

**关键数据点**:
- 补偿代码增长: 20 倍
- 状态追踪复杂度: O(n²)
- 最终化延迟: 5 倍
- 所有数据都在表格中可查

---

### 🏗️ 架构师
**目标**: 为 Seth 评估和改进建议

**推荐路线**:
```
第 1 步: SETH_IMPLEMENTATION_SUMMARY.md 
    → 问题分析和改进建议部分
    
第 2 步: CROSS_SHARD_DESIGN_GUIDE.md
    → 三个设计模式比较
    → 安全威胁分析
    
第 3 步: 性能考虑表格
    成本对比
    优化建议
```

**架构决策表**:

| 决策 | 理由 | 成本 |
|------|------|------|
| 补偿库 | 快速减轻负担 | 低 |
| 协议补偿器 | 系统解决 | 高 |
| 有限回滚 | 根本解决 | 很高 |

---

## 🔍 如何使用这些合约

### 场景 1：学习和理解

```python
# 1. 部署合约
pool = deploy_amm_pool(initial_x=10000, initial_y=10000)

# 2. 成功的交换
tx1 = pool.swap(amount_x=100, min_y=80)
# 结果: 获得 98Y ✅

# 3. 失败的交换
tx2 = pool.swap(amount_x=100, min_y=5000)
# 结果: 获得 0Y，状态标记为 FAILED ❌

# 4. 手动补偿
pool.refund_failed_swap(tx2.swap_id)
# 结果: 发出补偿事件
```

### 场景 2：性能测试

```python
# 测试不同的滑点设置
configs = [
    (1%, "保守"),
    (2%, "标准"),
    (5%, "激进"),
]

for slippage, label in configs:
    test_multi_hop_with_slippage(slippage)
    measure_finalization_time()
    measure_compensation_overhead()
```

### 场景 3：安全审计

```python
# 测试防护机制
test_double_spend_prevention()      # Nonce
test_replay_attack_prevention()     # 签名
test_emergency_withdrawal()         # 超时处理
test_shard_availability_fallback()  # 跨分片故障
```

---

## 📈 学习进度检查

完成以下任务来验证理解：

### Level 1: 理解问题
- [ ] 解释为什么无回滚导致开发者负担增加
- [ ] 描述一个失败的多跳交换会发生什么
- [ ] 列出三个主要差异（vs 标准链）

### Level 2: 设计解决方案
- [ ] 对比三个设计模式的优缺点
- [ ] 选择一个模式为 Alice 的场景编码
- [ ] 估计时间复杂度和 Gas 成本

### Level 3: 实现
- [ ] 修改 AMMPool 合约添加新特性
- [ ] 实现你自己的补偿逻辑
- [ ] 测试安全威胁场景

### Level 4: 优化
- [ ] 实现批量补偿
- [ ] 优化 Gas 使用
- [ ] 添加新的事件/监控

---

## 🔧 常见任务

### 任务 1：修改滑点检查

**文件**: `seth3.py` → `AMM_POOL_SOL`

```solidity
// 当前：简单的最小值检查
if (amountYOut < minYOut) {
    // 失败
}

// 修改为：基于池状态的动态检查
uint expectedPrice = (reserveY * 10^18) / reserveX;
uint slippagePercent = ((expectedPrice - currentPrice) * 100) / expectedPrice;
if (slippagePercent > maxSlippage) {
    // 失败
}
```

### 任务 2：添加超时机制

**文件**: `seth3.py` → `AMM_ROUTER_SOL`

```solidity
// 添加到 multiHopSwap
mapping(uint => uint256) swapStartTime;

function handleTimeout(uint swapId) {
    require(block.timestamp > swapStartTime[swapId] + 1 hours);
    // 自动补偿
}
```

### 任务 3：实现乐观执行

**文件**: `seth3.py` → 新合约 `OptimisticAMM`

```solidity
function executeOptimistic(uint amountIn) 
    returns (uint estimatedOut) {
    // 立即返回估计
    return estimateSwap(amountIn);
    // 后台异步验证
}
```

---

## ❓ 常见问题

### Q1: 这个测试如何证明论文的观点？

**A**: 
1. 成功交换 → 演示协议正常工作
2. 失败交换 → 演示无自动回滚
3. 手动补偿 → 演示开发者负担
4. 多跳失败 → 演示复杂性爆炸

数据来自于这 4 个场景的度量。

### Q2: 我应该使用哪个设计模式？

**A**:
- 金融/关键操作？ → **多阶段** (安全优先)
- 高吞吐量? → **乐观** (速度优先)
- 大量小交易? → **批处理** (成本优先)

### Q3: 补偿需要多长时间？

**A**: 
- 单个补偿: 2-5 秒（分片响应时间）
- n-hop 失败: n × 补偿时间
- 例: 3-hop = 6-15 秒

### Q4: 如何防止双重支出？

**A**: 
- 使用递增 Nonce
- 检查 `require(nonce == expectedNonce++)`
- 在发送前验证

### Q5: 这些合约能用于生产吗？

**A**: 
- 测试合约: ❌ 不能，仅供教学
- 设计原则: ✅ 可以
- 扩展它们: ✅ 添加更多检查后可以

---

## 📚 补充资源

### 相关概念

1. **AMM (Automated Market Makers)**
   - Constant Product Formula: X × Y = K
   - Slippage 滑点
   - Liquidity Pools 流动性池

2. **分布式系统**
   - 异步通信
   - 一致性模型
   - 补偿事务

3. **区块链**
   - 分片架构
   - 跨链交互
   - 原子性保证

### 推荐阅读

- Uniswap V2 白皮书 (理解 AMM)
- Stripe 补偿事务论文 (理解补偿模式)
- Seth 白皮书 (理解分片设计)

---

## 🚀 下一步

### 短期 (1 周内)
1. 阅读快速参考和测试设计
2. 运行 seth3.py 看实际效果
3. 修改一个参数观察变化

### 中期 (2-4 周内)
1. 实现一个自己的设计模式
2. 添加新的测试场景
3. 性能基准测试

### 长期 (1 个月+)
1. 贡献补偿库
2. 参与协议级改进
3. 审计真实的跨分片合约

---

## 💬 反馈和改进

如果你有以下问题，请查看对应部分：

- "为什么?" → `AMM_CROSS_SHARD_TEST_DESIGN.md`
- "怎么做?" → `CROSS_SHARD_DESIGN_GUIDE.md`
- "快速查找?" → `AMM_QUICK_REFERENCE.md`
- "全面了解?" → `SETH_IMPLEMENTATION_SUMMARY.md`
- "看代码?" → `seth3.py`

---

**祝你学习愉快！** 🎉

通过这些资源，你将深刻理解无回滚协议的权衡，
学到在异步分布式系统上编写正确合约的技巧。
