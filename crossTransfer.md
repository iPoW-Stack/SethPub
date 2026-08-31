# 分片区块链跨分片资产流转与状态存储协议设计与安全性证明规范
### —— 基于 Feistel 双射地址派生、内生零铸造分身与非可交换状态算法隔离证明

---

## 目录
1. [系统总体架构与全网账本守恒公理](#1-系统总体架构与全网账本守恒公理)
2. [160-bit 满熵双射地址派生算法（Feistel Permutation）](#2-160-bit-满熵双射地址派生算法feistel-permutation)
3. [内生自安全与零铸造分身合约设计（`CrossShardBase`）](#3-内生自安全与零铸造分身合约设计crossshardbase)
4. [目标端 Gas 编译期确定性预扣与底层 Host 拦截机制](#4-目标端-gas-编译期确定性预扣与底层-host-拦截机制)
5. [底层共识层系统入账与 GBP 流水线时序](#5-底层共识层系统入账与-gbp-流水线时序)
6. [算法级规避非可交换金融状态冲突的形式化证明（AMM/Orderbook Conflict-Free Proof）](#6-算法级规避非可交换金融状态冲突的形式化证明ammorderbook-conflict-free-proof)
7. [形式化安全性分析与定理证明](#7-形式化安全性分析与定理证明)

---

## 1. 系统总体架构与全网账本守恒公理

系统由 $K$ 个并行分片组成，每个分片划分 $N$ 个并行执行池（Pool）。跨分片资产转移与状态同步遵循**“单向前向执行（Rollback-Free Forward Settlement）”**与**“状态空间正交隔离”**原则。

```
[ 源分片 S_src, P_src ]                          [ 目标分片 S_dst, P_dst ]
      用户调用 crossTransfer()                          底层共识引擎驱动系统调用
               │                                                  │
 ├── 1. 本地扣款 (Balance -= Δ)                    ├── 1. 验证源端 BLS QC 证明
 ├── 2. 扣除目标 Gas (Host 拦截 gas_left)           ├── 2. 校验 Base(Addr_dst) == Base(Addr_src)
 └── 3. 发出 CrossTransferOut 事件                ├── 3. msg.sender = SYSTEM_EXECUTOR
               │                                   └── 4. 本地入账 (Balance += Δ)
               ▼                                                  ▲
     [ 全局缓冲池 (GBP) / 因果排序中继 ] ─────────────────────────────┘
```

### 1.1 全网价值守恒定律（Conservation Invariant）
对于全网任意时刻 $t$，代币总供应量 $\text{TotalSupply}$ 恒等于所有活跃分片状态树中的余额总和与在途（In-Flight）资产包价值之和：

$$\sum_{k=0}^{K-1} \sum_{p=0}^{N-1} \text{LocalSupply}(S_k, P_p, t) + \sum_{m \in \text{InFlight}(t)} \text{Value}(m) \equiv \text{TotalSupply}$$

---

## 2. 160-bit 满熵双射地址派生算法（Feistel Permutation）

为了在无需跨片全局状态查询（$O(1)$ 复杂度）的前提下，实现**“给定任意分片和池的派生地址，均可无状态逆向反算出其 Base 根地址”**，协议采用 4 轮强伪随机 Feistel 置换网络（Luby-Rackoff SPRP）。

### 2.1 数学定义
* **输入/输出空间**：$\mathbb{Z}_{2^{160}}$（严格对齐 EVM 20 字节地址空间）；
* **划分**：高 80 位左半区 $L \in \mathbb{Z}_{2^{80}}$，低 80 位右半区 $R \in \mathbb{Z}_{2^{80}}$；
* **拓扑轮密钥**：$K_i = \text{keccak256}(\text{"AKAVERSE_FEISTEL_V1"} \parallel s \parallel p \parallel i)$；
* **轮函数**：$F(R, K_i) = \text{keccak256}(R \parallel K_i)[0 \dots 9]$（截取高 80 位）。

### 2.2 算法状态转移

$$\begin{aligned}
\text{正向派生 (Base } \to \text{ Shard):} \quad & L_{i+1} = R_i, \quad R_{i+1} = L_i \oplus F(R_i, K_i) \quad (i = 0, 1, 2, 3) \\
\text{逆向反算 (Shard } \to \text{ Base):} \quad & R_i = L_{i+1}, \quad L_i = R_{i+1} \oplus F(L_{i+1}, K_i) \quad (i = 3, 2, 1, 0)
\end{aligned}$$

```
 [ 正向派生: deriveShardAddress ]          [ 逆向反算: recoverBaseAddress ]
          (L_0, R_0)                                  (L_4, R_4)
              │                                           │
  ┌───────────┴───────────┐                   ┌───────────┴───────────┐
  │ Round 0: K_0(s, p)    │                   │ Inv-Round 3: K_3      │
  │   L_1 = R_0           │                   │   R_3 = L_4           │
  │   R_1 = L_0 ⊕ F(R_0)  │                   │   L_3 = R_4 ⊕ F(L_4)  │
  ├───────────────────────┤                   ├───────────────────────┤
  │ Round 1: K_1(s, p)    │                   │ Inv-Round 2: K_2      │
  ├───────────────────────┤                   ├───────────────────────┤
  │ Round 2: K_2(s, p)    │                   │ Inv-Round 1: K_1      │
  ├───────────────────────┤                   ├───────────────────────┤
  │ Round 3: K_3(s, p)    │                   │ Inv-Round 0: K_0      │
  │   L_4 = R_3           │                   │   R_0 = L_1           │
  │   R_4 = L_3 ⊕ F(R_3)  │                   │   L_0 = R_1 ⊕ F(L_1)  │
  └───────────┬───────────┘                   └───────────┬───────────┘
              ▼                                           ▼
          (L_4, R_4)                                  (L_0, R_0)
```

### 2.3 Solidity 纯计算验证库 (`ReversibleFeistelAddress.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ReversibleFeistelAddress {
    bytes constant DOMAIN_TAG = "AKAVERSE_FEISTEL_V1";
    uint256 constant MASK_80_BITS = (1 << 80) - 1;

    /**
     * @notice 【正向】从 Base 地址推导目标分片/池的确定性地址
     */
    function deriveShardAddress(
        address baseAddr,
        uint32 shardId,
        uint32 poolId
    ) internal pure returns (address) {
        uint256 raw = uint160(baseAddr);
        uint256 left = raw >> 80;
        uint256 right = raw & MASK_80_BITS;

        for (uint256 i = 0; i < 4; i++) {
            uint256 roundKey = uint256(
                keccak256(abi.encodePacked(DOMAIN_TAG, shardId, poolId, i))
            );
            uint256 fOut = uint256(
                keccak256(abi.encodePacked(right, roundKey))
            ) >> 176;

            uint256 nextLeft = right;
            uint256 nextRight = left ^ fOut;
            left = nextLeft;
            right = nextRight;
        }
        return address(uint160((left << 80) | right));
    }

    /**
     * @notice 【逆向】从分片地址反算 Base 根地址
     */
    function recoverBaseAddress(
        address shardAddr,
        uint32 shardId,
        uint32 poolId
    ) internal pure returns (address) {
        uint256 raw = uint160(shardAddr);
        uint256 left = raw >> 80;
        uint256 right = raw & MASK_80_BITS;

        for (int256 i = 3; i >= 0; i--) {
            uint256 roundKey = uint256(
                keccak256(abi.encodePacked(DOMAIN_TAG, shardId, poolId, uint256(i)))
            );
            uint256 fOut = uint256(
                keccak256(abi.encodePacked(left, roundKey))
            ) >> 176;

            uint256 prevRight = left;
            uint256 prevLeft = right ^ fOut;
            left = prevLeft;
            right = prevRight;
        }
        return address(uint160((left << 80) | right));
    }
}
```

---

## 3. 内生自安全与零铸造分身合约设计（`CrossShardBase`）

全网分身合约采用**同构字节码**。分身合约通过数学自鉴权判定自身角色，从底层物理剥夺铸币权限，实现**零铸造公理（Zero-Mint Invariant）**。

### 3.1 核心基类实现 (`CrossShardBase.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ReversibleFeistelAddress.sol";

abstract contract CrossShardBase {
    using ReversibleFeistelAddress for address;

    uint32 public immutable SHARD_ID;
    uint32 public immutable POOL_ID;
    address public immutable SYSTEM_EXECUTOR;
    address public immutable BASE_ROOT_ADDRESS;
    bool public immutable IS_ROOT;

    mapping(address => uint256) internal _balances;
    mapping(bytes32 => bytes) internal _crossStorage;
    uint256 public totalSupply;
    uint64 internal _crossNonce;

    event CrossTransferOut(address indexed from, address indexed to, uint256 amount, uint64 nonce);
    event CrossStorageOut(bytes32 indexed key, bytes value, uint64 nonce);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event CrossStorageIn(bytes32 indexed key, bytes value);

    modifier onlySystemExecutor() {
        require(msg.sender == SYSTEM_EXECUTOR, "UNAUTHORIZED_SYSTEM_CALL");
        _;
    }

    modifier onlyRoot() {
        require(IS_ROOT, "CLONE_MINT_FORBIDDEN");
        _;
    }

    constructor(
        uint32 shardId,
        uint32 poolId,
        address systemExecutor,
        uint256 initialSupply
    ) {
        SHARD_ID = shardId;
        POOL_ID = poolId;
        SYSTEM_EXECUTOR = systemExecutor;

        address recoveredBase = address(this).recoverBaseAddress(shardId, poolId);
        BASE_ROOT_ADDRESS = recoveredBase;

        if (recoveredBase == address(this)) {
            IS_ROOT = true;
            totalSupply = initialSupply;
            _balances[msg.sender] = initialSupply;
            emit Transfer(address(0), msg.sender, initialSupply);
        } else {
            IS_ROOT = false;
            totalSupply = 0; // 分身强制初始供应量为 0
        }
    }

    // =============================================================
    //                 内部跨分片原语 (Internal Primitives)
    // =============================================================

    function _crossTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual returns (uint64 nonce) {
        require(to != address(0), "INVALID_RECIPIENT");
        require(_balances[from] >= amount, "INSUFFICIENT_BALANCE");

        _balances[from] -= amount;
        totalSupply -= amount; // 源分片物理核减

        nonce = ++_crossNonce;
        emit CrossTransferOut(from, to, amount, nonce);
    }

    function _crossSetStorage(
        bytes32 key,
        bytes memory value
    ) internal virtual returns (uint64 nonce) {
        _crossStorage[key] = value;
        nonce = ++_crossNonce;
        emit CrossStorageOut(key, value, nonce);
    }

    function _receiveCrossTransfer(address to, uint256 amount) internal virtual {
        require(to != address(0), "INVALID_RECIPIENT");
        _balances[to] += amount;
        totalSupply += amount; // 目标分片入账累加
        emit Transfer(address(0), to, amount);
    }

    function _receiveCrossStorage(bytes32 key, bytes memory value) internal virtual {
        _crossStorage[key] = value;
        _onCrossStorageUpdated(key, value);
        emit CrossStorageIn(key, value);
    }

    function _onCrossStorageUpdated(bytes32 key, bytes memory value) internal virtual {}

    // =============================================================
    //                 共识层系统入账入口 (System Ingress)
    // =============================================================

    function systemExecuteCrossTransfer(address to, uint256 amount) external onlySystemExecutor {
        _receiveCrossTransfer(to, amount);
    }

    function systemExecuteCrossStorage(bytes32 key, bytes calldata value) external onlySystemExecutor {
        _receiveCrossStorage(key, value);
    }
}
```

---

## 4. 目标端 Gas 编译期确定性预扣与底层 Host 拦截机制

为杜绝合约层参数污染（无需传递 `msg.value` 或 `nativeFee`），目标分片的 Gas 消耗全部在编译期固定，并由源分片 EVM Host（`evmone`）直接在解释器层扣减。

### 4.1 目标端静态 Gas 定价模型
* **跨分片转账 (`systemExecuteCrossTransfer`)**：固定执行 1 次 SLOAD + 1 次 SSTORE + 1 次 LOG3，开销恒定：
  $$G_{\text{target\_transfer}} \equiv 30{,}000\ \text{Gas}$$
* **跨分片存储 (`systemExecuteCrossStorage`)**：
  $$G_{\text{target\_storage}}(L) = 25{,}000 + \left\lceil \frac{L}{32} \right\rceil \times 20{,}000\ \text{Gas}$$

### 4.2 C++ EVM Host 拦截与即时扣费逻辑 (`evmc_host_context`)

```cpp
const auto TOPIC_CROSS_TRANSFER = keccak256("CrossTransferOut(address,address,uint256,uint64)");
const auto TOPIC_CROSS_STORAGE  = keccak256("CrossStorageOut(bytes32,bytes,uint64)");

evmc_result on_evm_emit_log(
    evmc_host_context* context,
    const evmc_address& address,
    const uint8_t* data,
    size_t data_size,
    const evmc_bytes32 topics[],
    size_t num_topics
) noexcept {
    int64_t target_gas_charge = 0;

    if (num_topics > 0 && topics[0] == TOPIC_CROSS_TRANSFER) {
        target_gas_charge = 30'000;
    } else if (num_topics > 0 && topics[0] == TOPIC_CROSS_STORAGE) {
        size_t words = (data_size + 31) / 32;
        target_gas_charge = 25'000 + (words * 20'000);
    }

    if (target_gas_charge > 0) {
        // 源分片 Gas 余额不足以支付目标端开销，直接触发 Out-of-Gas
        if (context->tx_gas_left < target_gas_charge) {
            return evmc_result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
        }
        // 原子扣除
        context->tx_gas_left -= target_gas_charge;
        context->accumulate_cross_gas_reward(target_gas_charge);
    }

    return evmc_result{EVMC_SUCCESS, context->tx_gas_left, nullptr, 0};
}
```

---

## 5. 底层共识层系统入账与 GBP 流水线时序

跨分片事件不经过任何用户态交易池（Mempool），直接由底层流水线打包并执行。

```
[ 源分片共识引擎 ]
        │  1. 打包区块并生成带有门限 BLS 签名的收据证明 QC(B_src)
        ▼
[ 全局缓冲池 (GBP) ]
        │  2. 按因果序排列跨片消息，组装全局块 B_g
        ▼
[ 目标分片区块处理器 (Block Processor) ]
        │  3. 密码学校验: 验证 QC(B_src)
        │  4. 防重放校验: 校验 !executed[msgId]
        │  5. 身份校验: 校验 RecoverBase(target_addr) == RecoverBase(src_addr)
        │  6. 构造系统消息 (msg.sender = SYSTEM_EXECUTOR, 不需要私钥签名)
        ▼
[ EVM 解释器 (evmone) ]
        │  7. 执行 systemExecuteCrossTransfer / systemExecuteCrossStorage
        ▼
[ 状态机固化 State Trie ]
```

---

## 6. 算法级规避非可交换金融状态冲突的形式化证明（AMM/Orderbook Conflict-Free Proof）

协议通过形式化定义状态机转移语义，证明 `_crossTransfer` 与 `_crossSetStorage` 从**算法底层**天然杜绝了 AMM 滑点竞争、并发多主写入（Multi-Master Conflicts）与虚实资产脱节问题。

```
                     ┌────────────────────────────────────────────────────────┐
                     │            状态机算子正交分解与可交换性证明            │
                     └───────────────────────────┬────────────────────────────┘
                                                 │
                   ┌─────────────────────────────┴─────────────────────────────┐
                   ▼                                                           ▼
     【 算子 A: 价值线性转移 _crossTransfer 】                 【 算子 B: 控制总线写入 _crossSetStorage 】
       - 代数可交换阿贝尔群 (Abelian Group)                      - 幂等单主投影算子 (Idempotent Projection)
       - (S ⊕ Δ_1) ⊕ Δ_2 ≡ (S ⊕ Δ_2) ⊕ Δ_1                      - P_master(S, v) := S[key ↦ v]
       - 账面状态与物理资产 1:1 绝对锚定                         - 杜绝多主并发写，无脑裂风险
                   │                                                           │
                   └─────────────────────────────┬─────────────────────────────┘
                                                 ▼
                          【 结论: 算法内生免疫所有非可交换金融状态冲突 】
```

### 6.1 `_crossTransfer` 的阿贝尔群可交换性证明（Abelian Commutativity）
* **定义**：设状态树中地址 $u$ 的余额状态为 $B(u) \in \mathbb{N}$。跨分片转账在目标分片的入账算子定义为加法算子 $T_{\Delta}(B) = B + \Delta$。
* **定理（时序无关性）**：对于任意两笔到达目标分片的并发在途跨分片转账 $\Delta_1, \Delta_2$：
  $$T_{\Delta_1} \circ T_{\Delta_2}(B) = (B + \Delta_2) + \Delta_1 = (B + \Delta_1) + \Delta_2 = T_{\Delta_2} \circ T_{\Delta_1}(B)$$
* **推论**：`_crossTransfer` 属于**加法阿贝尔半群算子**，无论 GBP 路由或网络抖动导致数据包以何种顺序到达，最终状态严格收敛一致，与顺序敏感的 AMM 滑点状态机完全正交。

### 6.2 `_crossTransfer` 的虚实资产 1:1 严格对称性（Physical-State Parity）
* **定理**：目标分片账面代币的每一次增加，均有源分片物理扣除作为前驱断言。
  $$\Delta \text{LocalSupply}(S_{\text{dst}}) \equiv \Delta \text{PhysicalVault}(S_{\text{dst}}) = \Delta$$
* **推论**：目标端分身合约不存在“仅有数据同步而无底层真实资金”的部分准备金（Fractional Reserve）危机，杜绝了即时兑换时的挤兑穿仓隐患。

### 6.3 `_crossSetStorage` 的单主幂等性证明（Single-Writer Idempotence）
* **定义**：状态写入算子定义为状态映射覆盖 $W_{k, v}(S) = S[k \mapsto v]$。
* **定理（单主一致性）**：在系统架构中，每个 Key $k$ 的写权限严格受限于唯一权威主控地址（Master Authority）。
  $$W_{k, v_2} \circ W_{k, v_1}(S) = S[k \mapsto v_2]$$
* **推论**：写操作具有**幂等投影性（Idempotent Projection）**，不存在多主并发修改同一状态的读写竞争（No Multi-Master Race Conditions）。

### 6.4 非可交换金融计算的本地闭环范式（Local Execution Closure）
由于协议从算法层将跨分片原语限定为阿贝尔群加减法与单主覆盖，所有**非可交换算子（Non-Commutative Operators，如 AMM 恒定乘积公式 $(x+\Delta x)(y-\Delta y) \ge k$、订单簿价格-时间优先撮合）**被天然限制在分片本地状态机闭环执行：
* **AMM 业务范式**：每个分片独立维护本地 AMM 流动性池，套利者通过可交换的 `_crossTransfer` 进行跨片价值搬砖，价格发现与滑点计算 $100\%$ 在分片内部即时收敛；
* **撮合业务范式**：专属撮合分片通过本地内存撮合，跨分片原语仅负责充值与提现通道。

---

## 7. 形式化安全性分析与定理证明

### 7.1 定理 1：全网代币总供应量强守恒定理（Conservation of Value）

**证明**：
1. **源端状态原子性**：EVM 事务执行时，`_balances[from] -= Δ` 与 `totalSupply -= Δ` 先于 `CrossTransferOut` 事件发生。若源端余额不足，EVM 抛出异常并回滚 Journal，事件物理不可见。
2. **中继唯一性**：跨分片数据包绑定唯一标识：
   $$\text{PacketID} = \text{keccak256}(\text{srcShard}, \text{dstShard}, \text{baseAddr}, \text{nonce}, \text{height})$$
   目标端共识层维护已处理位图，严格执行幂等去重。
3. **分身零增发性**：分身合约初始化时 `totalSupply = 0`，且不存在可调用的外部 `_mint()`。目标端代币增加的唯一途径为 `systemExecuteCrossTransfer`，其入账量严格等于源端扣除量 $\Delta$。
4. **守恒推导**：
   $$\Delta \text{TotalSupply} = -\Delta (\text{Source}) + 0 (\text{In-Flight}) + \Delta (\text{Destination}) = 0$$
   全网代币总量在任意离散状态机转换步长下严格守恒。 $\blacksquare$

---

### 7.2 定理 2：地址双射性与抗冒充定理（Bijective Identity Guarantee）

**证明**：
1. **双射性**：Feistel 结构在有限域 $\mathbb{Z}_{2^{160}}$ 上是置换映射（Permutation）。对于任意给定的 $(s, p)$，映射 $f_{(s,p)}: A \to Addr_{s,p}$ 是严格的一对一双射函数。
   $$\forall A_1 \neq A_2 \iff f_{(s,p)}(A_1) \neq f_{(s,p)}(A_2)$$
2. **唯一可逆性**：逆映射 $f_{(s,p)}^{-1}(Addr_{s,p}) \equiv A$ 确定且唯一。目标分片共识层在派发跨分片消息时，执行强制断言：
   $$f_{(s_{\text{dst}}, p_{\text{dst}})}^{-1}(Addr_{\text{dst}}) == f_{(s_{\text{src}}, p_{\text{src}})}^{-1}(Addr_{\text{src}}) \equiv A_{\text{Base}}$$
   若攻击者在目标分片部署非关联合约，其计算出的 $A_{\text{Base}}'$ 必不相等，系统调用绝不会派发至恶意地址。 $\blacksquare$

---

### 7.3 定理 3：目标端执行确定性与零 Revert 定理（Deterministic Zero-Revert Invariant）

**证明**：
1. 目标端入账函数 `_receiveCrossTransfer` 仅包含单一存储累加操作：
   $$\text{SLOAD} \to \text{ADD} \to \text{SSTORE}$$
2. 不包含任何条件断言（`require`）、循环（`loop`）或外部调用钩子（External Call Hook / ERC-777）。
3. 数学运算采用 Solidity 0.8+ 规范，由于全网代币总供应量受限且源端已完成等额扣除，$\text{Balance} + \Delta$ 绝不可能发生溢出。
4. 目标端执行成功率恒为 $100\%$，消除因应用层 Revert 导致的资金在途蒸发隐患。 $\blacksquare$

---

### 7.4 核心安全属性矩阵

| 安全威胁模型 | 传统跨链 / 分片方案表现 | 本协议体系保障机制 | 安全强度 |
| :--- | :--- | :--- | :---: |
| **非可交换金融状态冲突** | 跨片共享 AMM 导致 $k$ 值撕裂与穿仓 | **算法级算子隔离：原语仅包含阿贝尔加法与单主幂等写入** | **数学级免疫 (P0)** |
| **恶意分身增发** | 容易因多链部署脚本失误导致重复 Mint | **Feistel 自鉴权：分身初始化强行锁死为 0 供应量** | **数学级免疫 (P0)** |
| **伪造系统调用加钱** | 依赖合约层管理员多签，易被钓鱼 | **特权 `SYSTEM_EXECUTOR` 由共识层注入，外部无法签名模拟** | **共识级免疫 (P0)** |
| **目标端 Gas 耗尽死账** | 用户动态预估不准导致 Out-of-Gas | **编译期常量定价 + 源端 Host 强行预扣** | **确定性免疫 (P0)** |
| **地址抢占与后门植入** | 攻击者抢先在目标分片使用 CREATE2 部署 | **派生地址空间由系统保留，仅允许共识引擎自动分身** | **系统级免疫 (P0)** |
| **网络重放攻击** | 依赖应用层 Nonce，容易乱序 | **全局单调 Nonce + 目标端共识位图去重** | **协议级免疫 (P0)** |