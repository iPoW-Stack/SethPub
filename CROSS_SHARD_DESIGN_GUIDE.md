# 无回滚协议中的跨分片合约设计指南

## 高层概述

本文档为在 Seth 区块链上编写跨分片智能合约的开发者提供实践指南。结合论文 *"The Burden on Smart Contract Composability"* 的分析，我们提供了应对异步无回滚环境的设计模式和最佳实践。

---

## 目录

1. [核心概念](#核心概念)
2. [设计模式](#设计模式)
3. [实现指南](#实现指南)
4. [性能考虑](#性能考虑)
5. [安全性](#安全性)
6. [案例研究](#案例研究)

---

## 核心概念

### 无回滚协议的特点

| 特性 | 说明 | 影响 |
|------|------|------|
| **前向移动** | 所有交易只能前进，不能撤销 | 需要显式补偿 |
| **异步状态托管** | 分片之间不强制同步 | 可能状态不一致 |
| **原子性缺失** | 操作不保证全部成功或全部失败 | 需要手动处理失败 |

### 问题分类

#### 问题 1：部分失败

```solidity
// ❌ 危险：hop2 可能失败，但 hop1 已执行
function swapX_Y_Z(uint amountX) {
    uint y = swapPool1.swapX_Y(amountX);  // ✅ 成功
    uint z = swapPool2.swapY_Z(y);        // ❌ 可能失败
    // 现在 y 被卡在 swapPool2
}
```

**原因**：不同分片的池可能有不同的流动性约束

**解决**：显式多阶段流程

```solidity
// ✅ 安全：追踪每个阶段
contract SafeSwap {
    mapping(uint => SwapPhase) phases;
    
    function initiateSwap(uint amountX) returns (uint phaseId) {
        phaseId = nextPhaseId++;
        phases[phaseId].status = INITIATED;
        phases[phaseId].input = amountX;
    }
    
    function executeHop1(uint phaseId) onlyNotExecuted(phaseId) {
        uint y = swapPool1.swapX_Y(phases[phaseId].input);
        phases[phaseId].hop1Output = y;
        phases[phaseId].status = HOP1_COMPLETE;
    }
    
    function executeHop2(uint phaseId) onlyHop1Complete(phaseId) {
        uint z = swapPool2.swapY_Z(phases[phaseId].hop1Output);
        phases[phaseId].hop2Output = z;
        phases[phaseId].status = COMPLETE;
    }
    
    function compensate(uint phaseId) onlyFailed(phaseId) {
        if (phases[phaseId].status == HOP1_COMPLETE) {
            // 发送 hop1 输出退款到源分片
            sendCompensation(phaseId);
        }
    }
}
```

#### 问题 2：跨分片不一致

```
时间线：
  T1: Alice 在 ShardX 提交 100X
      ShardX: balance[Alice] = -100 ✅
      
  T2: AMM 在 ShardP 收到交换请求
      ShardP: 计算输出 = 98Y ✅
      
  T3: 滑点检查失败！
      ShardP: 交换失败 ❌
      
  T4: ShardX 还不知道失败（异步）
      ShardX: balance[Alice] = -100 ❌ 不一致！
      
  T5（延迟）: 补偿请求到达 ShardX
      ShardX: 发送 100X 回 Alice ✅
```

**解决**：使用 Escrow 模式

```solidity
// Shard X 上的 Escrow 合约
contract XSideEscrow {
    mapping(uint => EscrowRecord) escrows;
    
    function lockTokens(address from, uint amount, uint swapId) 
        returns (bool) {
        require(balance[from] >= amount);
        balance[from] -= amount;
        escrows[swapId].status = LOCKED;
        escrows[swapId].owner = from;
        escrows[swapId].amount = amount;
        emit TokensLocked(from, amount, swapId);
    }
    
    function commit(uint swapId) {
        require(escrows[swapId].status == LOCKED);
        escrows[swapId].status = COMMITTED;
        // 跨分片 AMM 已确认成功
    }
    
    function rollback(uint swapId) {
        require(escrows[swapId].status == LOCKED || 
                escrows[swapId].status == COMMITTED);
        address owner = escrows[swapId].owner;
        uint amount = escrows[swapId].amount;
        balance[owner] += amount;
        escrows[swapId].status = ROLLED_BACK;
        emit TokensReturned(owner, amount, swapId);
    }
}

// Shard P 上的 AMM 合约
contract AMMWithEscrow {
    function swapWithEscrow(uint swapId, uint minY)
        returns (bool success) {
        // 1. 检查 escrow 状态
        require(xSideEscrow.isLocked(swapId));
        
        // 2. 执行交换
        uint y = (X_INPUT * reserveY) / (reserveX + X_INPUT);
        
        // 3. 验证滑点
        if (y < minY) {
            // 触发补偿
            xSideEscrow.rollback(swapId);
            return false;
        }
        
        // 4. 标记为已提交
        xSideEscrow.commit(swapId);
        return true;
    }
}
```

#### 问题 3：交易最终化延迟

```
标准区块链：
  T1: 交易提交 → T2+1 块：最终化 (O(1))

Seth 无回滚协议（失败路径）：
  T1: Hop 1 提交到 ShardX
  T2: 等待 ShardX 确认 (L1)
  T3: Hop 2 提交到 ShardY
  T4: 等待 ShardY 确认 (L2)
  T5: Hop 2 失败，发送补偿请求到 ShardX
  T6: 等待 ShardX 补偿处理 (L3)
  T7: 最终化 (Σ Li >> 1 块)
```

**解决**：乐观执行 + 异步验证

```solidity
// 路由器：乐观继续，异步验证
contract OptimisticRouter {
    mapping(uint => RouteState) routes;
    
    function optimisticMultiHop(uint[] calldata swapIds, uint amountIn)
        returns (uint estimatedOut) {
        
        // 立即返回估计值（基于当前池状态）
        uint current = amountIn;
        for (uint i = 0; i < swapIds.length; i++) {
            current = estimateSwap(pools[i], current);
        }
        estimatedOut = current;
        
        // 异步验证每个 hop
        for (uint i = 0; i < swapIds.length; i++) {
            scheduleAsyncVerification(swapIds[i], i);
        }
        
        return estimatedOut;
    }
    
    function verifyHopAsync(uint swapId, uint hopIndex) 
        external onlyVerifier {
        // 验证后台运行
        // 如果失败，触发补偿链
        if (!verifySwap(swapId, hopIndex)) {
            triggerCompensationChain(swapId);
        }
    }
}
```

---

## 设计模式

### 模式 1：多阶段交换

**适用场景**：Multi-hop AMM 路由

**结构**：

```solidity
contract MultiPhaseSwap {
    enum Phase { INITIATED, HOP1_LOCKED, HOP1_COMPLETE, 
                 HOP2_LOCKED, HOP2_COMPLETE, COMPENSATED }
    
    struct SwapState {
        Phase phase;
        uint64 timestamp;
        uint256 hop1Input;
        uint256 hop1Output;
        uint256 hop2Input;
        uint256 hop2Output;
        address initiator;
        bytes compensationData;
    }
    
    mapping(uint => SwapState) swaps;
    
    // Phase 1: Lock tokens in Shard X
    function phase1Lock(uint swapId, uint amount) {
        require(swaps[swapId].phase == INITIATED);
        shard_x_escrow.lock(swapId, amount);
        swaps[swapId].hop1Input = amount;
        swaps[swapId].phase = HOP1_LOCKED;
    }
    
    // Phase 2: Execute first hop
    function phase2Execute(uint swapId) {
        require(swaps[swapId].phase == HOP1_LOCKED);
        uint out = executeSwap1(swapId);
        swaps[swapId].hop1Output = out;
        swaps[swapId].phase = HOP1_COMPLETE;
    }
    
    // Phase 3: Lock output for second hop
    function phase3Lock(uint swapId) {
        require(swaps[swapId].phase == HOP1_COMPLETE);
        shard_p_escrow.lock(swapId, swaps[swapId].hop1Output);
        swaps[swapId].phase = HOP2_LOCKED;
    }
    
    // Phase 4: Execute second hop
    function phase4Execute(uint swapId, uint minOut) {
        require(swaps[swapId].phase == HOP2_LOCKED);
        uint out = executeSwap2(swapId, minOut);
        if (out < minOut) {
            swaps[swapId].phase = COMPENSATED;
            triggerCompensation(swapId);
        } else {
            swaps[swapId].hop2Output = out;
            swaps[swapId].phase = HOP2_COMPLETE;
        }
    }
}
```

**优点**：
- ✅ 明确的失败点
- ✅ 易于追踪
- ✅ 清晰的补偿路径

**缺点**：
- ❌ 最终化时间长
- ❌ 更多交易数
- ❌ 更高的 Gas 成本

### 模式 2：乐观 + 异步验证

**适用场景**：高吞吐量但允许延迟一致性的应用

**结构**：

```solidity
contract OptimisticExecution {
    struct OptimisticTx {
        Phase phase;
        uint256 optimisticOutput;
        uint256 actualOutput;
        bool verified;
        bool compensationTriggered;
    }
    
    mapping(bytes32 => OptimisticTx) optimistic;
    
    // 步骤 1：立即返回估计值
    function executeOptimistic(uint amountIn)
        returns (uint estimatedOut) {
        bytes32 txId = keccak256(abi.encode(msg.sender, block.timestamp));
        estimatedOut = estimateOutWithSlippage(amountIn, 2%);
        optimistic[txId].optimisticOutput = estimatedOut;
        optimistic[txId].phase = OPTIMISTIC;
        return estimatedOut;  // 快速返回！
    }
    
    // 步骤 2：后台异步验证（由 oracle 或 sequencer）
    function verifyAsync(bytes32 txId) external onlyVerifier {
        require(optimistic[txId].phase == OPTIMISTIC);
        
        uint actualOut = actualExecutionResult[txId];
        optimistic[txId].actualOutput = actualOut;
        optimistic[txId].verified = true;
        
        if (actualOut < optimistic[txId].optimisticOutput) {
            // 滑点导致实际输出减少
            // 触发异步补偿
            triggerAsyncCompensation(txId, 
                optimistic[txId].optimisticOutput - actualOut);
            optimistic[txId].compensationTriggered = true;
        }
        
        optimistic[txId].phase = VERIFIED;
    }
}
```

**优点**：
- ✅ 快速响应时间
- ✅ 用户体验好
- ✅ 高吞吐量

**缺点**：
- ❌ 一致性延迟
- ❌ 需可信验证器
- ❌ 补偿成本

### 模式 3：Batch 补偿

**适用场景**：大量小交易的补偿处理

**结构**：

```solidity
contract BatchCompensation {
    struct CompensationBatch {
        uint256 batchId;
        uint256 totalAmount;
        uint256 compensatedAmount;
        uint256[] failedSwaps;
        Phase phase;
    }
    
    CompensationBatch[] batches;
    
    // 收集失败的交换
    function collectFailures() external {
        uint[] memory failures = getAllFailedSwaps();
        if (failures.length > MIN_BATCH_SIZE) {
            createCompensationBatch(failures);
        }
    }
    
    // 批量处理补偿
    function processBatch(uint batchId) external onlyCompensator {
        CompensationBatch storage batch = batches[batchId];
        require(batch.phase == READY);
        
        for (uint i = 0; i < batch.failedSwaps.length; i++) {
            uint swapId = batch.failedSwaps[i];
            uint refundAmount = getRefundAmount(swapId);
            
            // 跨分片补偿
            sendCompensation(swapId, refundAmount);
            batch.compensatedAmount += refundAmount;
        }
        
        batch.phase = COMPLETED;
    }
}
```

**优点**：
- ✅ 减少交易数
- ✅ 降低成本
- ✅ 提高吞吐量

**缺点**：
- ❌ 补偿延迟增加
- ❌ 批量依赖关系复杂

---

## 实现指南

### 步骤 1：设计交换状态机

```python
class SwapStateMachine:
    states = {
        'INITIATED': 0,      # 交换请求创建
        'LOCKED': 1,         # 源分片锁定资金
        'EXECUTING': 2,      # AMM 处理中
        'EXECUTED': 3,       # AMM 完成
        'FAILED': 4,         # 检测到失败
        'COMPENSATING': 5,   # 补偿进行中
        'COMPENSATED': 6,    # 补偿完成
    }
    
    transitions = {
        'INITIATED': ['LOCKED'],
        'LOCKED': ['EXECUTING', 'FAILED'],
        'EXECUTING': ['EXECUTED', 'FAILED'],
        'EXECUTED': ['COMPLETED'],
        'FAILED': ['COMPENSATING'],
        'COMPENSATING': ['COMPENSATED'],
    }
```

### 步骤 2：定义错误处理

```solidity
enum Error {
    SLIPPAGE_EXCEEDED,
    INSUFFICIENT_LIQUIDITY,
    TIMEOUT_EXCEEDED,
    CROSS_SHARD_UNAVAILABLE,
    COMPENSATION_FAILED,
    INVALID_STATE_TRANSITION
}

mapping(uint => Error) swapErrors;

function recordError(uint swapId, Error err) internal {
    swapErrors[swapId] = err;
    emit ErrorRecorded(swapId, uint8(err));
}
```

### 步骤 3：实现补偿回调

```solidity
contract CompensationReceiver {
    event CompensationReceived(
        address indexed recipient,
        uint256 amount,
        uint256 swapId,
        uint256 timestamp
    );
    
    function receiveCompensation(
        address recipient,
        uint256 amount,
        uint256 swapId
    ) external onlyCompensationSource {
        require(amount > 0);
        balance[recipient] += amount;
        emit CompensationReceived(recipient, amount, swapId, block.timestamp);
    }
}
```

### 步骤 4：添加超时机制

```solidity
uint256 constant TIMEOUT = 1 hours;

mapping(uint => uint256) swapInitTime;

function initiateLockWithTimeout(uint swapId, uint amount) {
    swapInitTime[swapId] = block.timestamp;
    lock(swapId, amount);
}

function handleTimeout(uint swapId) external {
    require(block.timestamp > swapInitTime[swapId] + TIMEOUT);
    require(swaps[swapId].phase != COMPLETED);
    
    // 自动补偿
    triggerCompensation(swapId);
}
```

---

## 性能考虑

### 成本分析

| 操作 | Gas 成本 | 分片延迟 | 总时间 |
|------|---------|---------|---------|
| 单 Hop | 50K | 2s | 2s |
| 2-Hop (成功) | 100K | 4s | 4s |
| 2-Hop (失败+补偿) | 150K | 6s + 补偿 | 10s+ |
| 批量补偿 (n=100) | 150K | 2s | 2s |

### 优化建议

**1. 预编译常见交换对**

```solidity
// 预编译 SETH-USDC 交换
function fastSwap(uint amountSETH) returns (uint amountUSDC) {
    // 使用预优化的路径，减少计算
    return (amountSETH * SETH_USDC_RATE) / 10**18;
}
```

**2. 使用 Batch 处理**

```solidity
function batchSwap(uint[] calldata amounts) returns (uint[] memory outputs) {
    uint n = amounts.length;
    uint[] memory outs = new uint[](n);
    
    for (uint i = 0; i < n; i++) {
        outs[i] = swapInternal(amounts[i]);  // 重用池状态
    }
    
    updatePoolOnce();  // 一次性更新，而非逐个更新
    return outs;
}
```

**3. 缓存池状态**

```solidity
struct CachedPoolState {
    uint256 reserveX;
    uint256 reserveY;
    uint256 lastUpdateBlock;
}

mapping(address => CachedPoolState) cache;

function getCachedRate(address pool) returns (uint rate) {
    if (cache[pool].lastUpdateBlock == block.number) {
        return calculateRate(cache[pool].reserveX, cache[pool].reserveY);
    }
    // 缓存过期，更新
    CachedPoolState memory fresh = getActualPoolState(pool);
    cache[pool] = fresh;
    return calculateRate(fresh.reserveX, fresh.reserveY);
}
```

---

## 安全性

### 威胁 1：Double Spend（双重支出）

**场景**：

```
Alice 在 Shard X 发送 100X 到 AMM
同时在另一个交易中也发送 100X

两个交易都锁定 200X（双重支出）
```

**防御**：

```solidity
// 使用 Nonce 防止重放
mapping(address => uint256) nonces;

function lock(address from, uint amount, uint nonce) {
    require(nonce == nonces[from]); // 严格递增
    nonces[from]++;
    // 锁定逻辑...
}
```

### 威胁 2：重放攻击

**场景**：

```
攻击者截获 compensationOrder
在不同的分片/时间重放它
造成多次补偿
```

**防御**：

```solidity
mapping(bytes32 => bool) processedOrders;

function processCompensation(
    uint256 swapId,
    address recipient,
    uint256 amount,
    bytes memory signature
) external {
    bytes32 orderHash = keccak256(abi.encode(
        swapId, recipient, amount, block.chainid, address(this)
    ));
    
    require(!processedOrders[orderHash], "Already processed");
    require(verifySignature(orderHash, signature), "Invalid signature");
    
    processedOrders[orderHash] = true;
    // 处理补偿
}
```

### 威胁 3：时间锁定

**场景**：

```
Alice 的资金被锁定在 Escrow
补偿流程失败或卡住
资金永久损失
```

**防御**：

```solidity
uint256 constant ESCROW_TIMEOUT = 1 days;

function emergencyWithdraw(uint swapId) external {
    require(msg.sender == escrows[swapId].owner);
    require(block.timestamp > escrows[swapId].lockTime + ESCROW_TIMEOUT);
    
    uint amount = escrows[swapId].amount;
    delete escrows[swapId];
    
    transferTokens(msg.sender, amount);
    emit EmergencyWithdrawal(swapId, amount);
}
```

---

## 案例研究

### 案例 1：SETH-USDC-DAI 三跳路由

**需求**：Alice 想交换 1000 SETH 为 DAI

**路径**：
1. SETH → USDC（Shard A, Pool A）
2. USDC → ETH（Shard B, Pool B）
3. ETH → DAI（Shard C, Pool C）

**实现**：

```solidity
contract ThreeHopRouter {
    address pool1; // Shard A
    address pool2; // Shard B  
    address pool3; // Shard C
    
    function execute(uint amountSETH, uint minDAI) 
        returns (uint finalAmount, uint swapId) {
        
        swapId = nextSwapId++;
        
        // Phase 1: Lock SETH
        escrowA.lock(msg.sender, amountSETH, swapId);
        
        // Phase 2: Execute hop 1
        uint usdc = pool1.swapXtoY(amountSETH);
        emit Hop1Complete(usdc);
        
        // Phase 3: Execute hop 2
        uint eth = pool2.swapXtoY(usdc);
        emit Hop2Complete(eth);
        
        // Phase 4: Execute hop 3
        uint dai = pool3.swapXtoY(eth);
        emit Hop3Complete(dai);
        
        // Check slippage
        if (dai < minDAI) {
            // Trigger compensation chain
            compensateAll(swapId, amountSETH, usdc, eth);
            return (0, swapId);
        }
        
        return (dai, swapId);
    }
    
    function compensateAll(
        uint swapId,
        uint sethAmount,
        uint usdcAmount,
        uint ethAmount
    ) internal {
        // Compensate Shard A: Return SETH
        compensator.trigger(A, swapId, sethAmount);
        
        // Compensate Shard B: Return USDC  
        compensator.trigger(B, swapId, usdcAmount);
        
        // Compensate Shard C: Return ETH
        compensator.trigger(C, swapId, ethAmount);
    }
}
```

### 案例 2：批量补偿处理

**需求**：处理 1000 个失败的交换的补偿

**实现**：

```solidity
contract BatchCompensationProcessor {
    function processBatch(uint[] calldata failedSwapIds) 
        external onlyCompensator {
        
        uint batchId = nextBatchId++;
        batches[batchId].createdAt = block.timestamp;
        batches[batchId].count = failedSwapIds.length;
        
        // Group by shard
        mapping(uint => uint[]) shardToSwaps;
        for (uint i = 0; i < failedSwapIds.length; i++) {
            uint swapId = failedSwapIds[i];
            uint shardId = getSourceShard(swapId);
            shardToSwaps[shardId].push(swapId);
        }
        
        // Process per shard
        for (uint shardId = 0; shardId < MAX_SHARDS; shardId++) {
            if (shardToSwaps[shardId].length > 0) {
                sendBatchCompensation(
                    shardId,
                    shardToSwaps[shardId],
                    batchId
                );
            }
        }
    }
}
```

---

## 总结建议

| 场景 | 推荐模式 | 原因 |
|------|---------|------|
| 关键金融操作 | 多阶段交换 | 安全性优先 |
| 高吞吐量应用 | 乐观执行 | 性能优先 |
| 批量补偿 | Batch处理 | 成本效益 |
| 普通交换 | 混合方法 | 平衡 |

### 检查清单

- [ ] 定义完整的状态机
- [ ] 实现所有 error 路径处理
- [ ] 添加超时机制
- [ ] 防护 double spend
- [ ] 防护重放攻击
- [ ] 实现紧急提取
- [ ] 测试补偿流程
- [ ] 监控和日志
- [ ] 性能基准测试
- [ ] 安全审计

---

## 相关资源

- `AMM_CROSS_SHARD_TEST_DESIGN.md` - 测试设计文档
- `seth3.py` - 实现示例
- Seth 文档 - 分片架构

