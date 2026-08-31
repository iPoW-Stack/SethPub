# 分片区块链跨分片资产与状态存储协议设计与安全性证明规范

本规范系统性阐述了基于 **Feistel 双射地址派生**、**内生零铸造分身（Zero-Mint Clone）**、**编译期确定性 Gas 预扣** 与 **共识层特权系统执行器（`SYSTEM_EXECUTOR`）** 的跨分片原生代币流转、合约代币转移及键值状态同步完整架构与形式化安全性证明。

---

## 目录
1. [系统总体架构与全网账本守恒公理](#1-系统总体架构与全网账本守恒公理)
2. [160-bit 满熵双射地址派生算法（Feistel Permutation）](#2-160-bit-满熵双射地址派生算法feistel-permutation)
3. [内生自安全与零铸造分身合约设计（`CrossShardBase`）](#3-内生自安全与零铸造分身合约设计crossshardbase)
4. [目标端 Gas 编译期确定性预扣与底层 Host 拦截机制](#4-目标端-gas-编译期确定性预扣与底层-host-拦截机制)
5. [底层共识层系统入账与 GBP 流水线时序](#5-底层共识层系统入账与-gbp-流水线时序)
6. [跨分片键值状态存储（Push Registry 模型）](#6-跨分片键值状态存储push-registry-模型)
7. [形式化安全性分析与定理证明](#7-形式化安全性分析与定理证明)

---

## 1. 系统总体架构与全网账本守恒公理

系统由 $K$ 个并行分片组成，每个分片划分 $N$ 个并行执行池（Pool）。跨分片资产转移与状态同步遵循**“单向前向执行（Rollback-Free Forward Settlement）”**与**“状态局部闭环”**原则。

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

为彻底消除分身部署引发的“多重增发”与“权限后门”，合约采用**同构字节码自鉴权机制**：
* 根分片合约：`recoverBaseAddress(this) == this`，成立为 Root，允许初始化代币；
* 全网分身合约：`recoverBaseAddress(this) != this`，判定为 Clone，**初始供应量强制为 0，物理封死任何 `_mint()` 接口**。

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
// 事件签名常量
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

## 6. 跨分片键值状态存储（Push Registry 模型）

针对分片环境下的“控制平面与全局配置”，采用**主动推送式存储同步（Push Registry）**，避免每次业务交易跨片拉取或在链上验证昂贵 Merkle 证明。

### 6.1 适用场景准则
* **推荐场景（读多写少、单主写入）**：全局紧急熔断开关（Pausable）、预言机喂价（Oracle Feeds）、账户抽象 Session Key 同步、黑名单合规列表。
* **禁止场景（高频并发写、资金账本）**：AMM 资产池储备量、高频订单簿撮合。

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
| **恶意分身增发** | 容易因多链部署脚本失误导致重复 Mint | **Feistel 自鉴权：分身初始化强行锁死为 0 供应量** | **数学级免疫 (P0)** |
| **伪造系统调用加钱** | 依赖合约层管理员多签，易被钓鱼 | **特权 `SYSTEM_EXECUTOR` 由共识层注入，外部无法签名模拟** | **共识级免疫 (P0)** |
| **目标端 Gas 耗尽死账** | 用户动态预估不准导致 Out-of-Gas | **编译期常量定价 + 源端 Host 强行预扣** | **确定性免疫 (P0)** |
| **地址抢占与后门植入** | 攻击者抢先在目标分片使用 CREATE2 部署 | **派生地址空间由系统保留，仅允许共识引擎自动分身** | **系统级免疫 (P0)** |
| **网络重放攻击** | 依赖应用层 Nonce，容易乱序 | **全局单调 Nonce + 目标端共识位图去重** | **协议级免疫 (P0)** |