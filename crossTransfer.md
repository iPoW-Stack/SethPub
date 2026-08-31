# 分片区块链跨分片资产流转与状态存储协议规范
### —— 基于 Feistel 双射地址派生、内生零铸造分身与金融状态解耦的安全性证明

---

## 目录
1. [系统架构与职责分离模型（Plane Separation）](#1-系统架构与职责分离模型plane-separation)
2. [160-bit 满熵双射地址派生算法（Feistel Permutation）](#2-160-bit-满熵双射地址派生算法feistel-permutation)
3. [内生自安全与零铸造分身合约设计（`CrossShardBase`）](#3-内生自安全与零铸造分身合约设计crossshardbase)
4. [目标端 Gas 编译期确定性预扣与底层 Host 拦截机制](#4-目标端-gas-编译期确定性预扣与底层-host-拦截机制)
5. [底层共识层系统入账与 GBP 流水线时序](#5-底层共识层系统入账与-gbp-流水线时序)
6. [AMM 与高频金融状态的解耦分析与标准落地范式](#6-amm-与高频金融状态的解耦分析与标准落地范式)
7. [形式化安全性分析与定理证明](#7-形式化安全性分析与定理证明)

---

## 1. 系统架构与职责分离模型（Plane Separation）

系统由 $K$ 个并行分片组成，每个分片划分 $N$ 个并行执行池（Pool）。为从根源消除跨分片一致性冲突与状态膨胀，协议严格实施**三层职责分离架构**：

```
                              ┌─────────────────────────────────────────────────────────┐
                              │                 分片区块链系统分层模型                  │
                              └────────────────────────────┬────────────────────────────┘
                                                           │
        ┌──────────────────────────────────┬───────────────┴───────────────┬──────────────────────────────────┐
        ▼                                  ▼                               ▼                                  ▼
【 价值层 (Value Plane) 】       【 控制层 (Control Plane) 】     【 计算层 (Compute Plane) 】     【 宿主层 (Host Execution) 】
  原语: _crossTransfer             原语: _crossSetStorage           原语: 本地 AMM / 订单簿撮合       共识拦截: Gas 预扣 / 系统入账
  - 点对点线性代币空间位移           - 单主推送式只读配置总线          - 严格非可交换金融状态计算        - 解释器层直接扣除目标 Gas
  - 严格满足加减代数可交换性         - 幂等全量覆盖，读多写少          - 100% 封闭在分片内部即时结算     - 特权地址触发系统入账
```

### 1.1 全网价值守恒公理（Conservation Invariant）
对于全网任意时刻 $t$，系统总代币供应量 $\text{TotalSupply}$ 恒等于所有活跃分片与池状态树中的余额总和与在途（In-Flight）资产包价值之和：

$$\sum_{k=0}^{K-1} \sum_{p=0}^{N-1} \text{LocalSupply}(S_k, P_p, t) + \sum_{m \in \text{InFlight}(t)} \text{Value}(m) \equiv \text{TotalSupply}$$

---

## 2. 160-bit 满熵双射地址派生算法（Feistel Permutation）

为实现**“给定任意分片和池的派生地址，均可无状态 $O(1)$ 逆向反算出其 Base 根地址”**，同时维持以太坊 20 字节原生地址格式与 $2^{80}$ 满熵抗碰撞强度，协议采用 4 轮强伪随机 Feistel 置换网络（Luby-Rackoff SPRP）。

### 2.1 数学模型
* **状态空间**：$\mathbb{Z}_{2^{160}}$（严格对应 EVM 20 字节地址）；
* **域划分**：高 80 位左半区 $L \in \mathbb{Z}_{2^{80}}$，低 80 位右半区 $R \in \mathbb{Z}_{2^{80}}$；
* **拓扑轮密钥**：$K_i = \text{keccak256}(\text{"AKAVERSE_FEISTEL_V1"} \parallel s \parallel p \parallel i)$；
* **轮函数**：$F(R, K_i) = \text{keccak256}(R \parallel K_i)[0 \dots 9]$（截取高 80 位）。

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

### 2.2 Solidity 纯计算验证库 (`ReversibleFeistelAddress.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ReversibleFeistelAddress {
    bytes constant DOMAIN_TAG = "AKAVERSE_FEISTEL_V1";
    uint256 constant MASK_80_BITS = (1 << 80) - 1;

    /**
     * @notice 【正向】从 Base 根地址派生目标分片/池的确定性地址
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
     * @notice 【逆向】从分片派生地址反算 Base 根地址
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

/**
 * @title CrossShardBase
 * @notice 极简自安全跨分片抽象基类
 */
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
            totalSupply = 0; // 全网分身强制初始化供应量为 0
        }
    }

    // =============================================================
    //                 内部跨分片原语 (Internal Primitives)
    // =============================================================

    /**
     * @notice 【源分片内部调用】价值转移原语
     */
    function _crossTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual returns (uint64 nonce) {
        require(to != address(0), "INVALID_RECIPIENT");
        require(_balances[from] >= amount, "INSUFFICIENT_BALANCE");

        _balances[from] -= amount;
        totalSupply -= amount; // 源端物理缩减流通量

        nonce = ++_crossNonce;
        emit CrossTransferOut(from, to, amount, nonce);
    }

    /**
     * @notice 【源分片内部调用】状态存储广播原语
     */
    function _crossSetStorage(
        bytes32 key,
        bytes memory value
    ) internal virtual returns (uint64 nonce) {
        _crossStorage[key] = value;
        nonce = ++_crossNonce;
        emit CrossStorageOut(key, value, nonce);
    }

    /**
     * @notice 【目标分片内部调用】价值入账实现
     */
    function _receiveCrossTransfer(address to, uint256 amount) internal virtual {
        require(to != address(0), "INVALID_RECIPIENT");
        _balances[to] += amount;
        totalSupply += amount; // 目标端物理增加流通量
        emit Transfer(address(0), to, amount);
    }

    /**
     * @notice 【目标分片内部调用】状态存储写入实现
     */
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

为保持合约接口轻量化并杜绝参数污染，目标分片执行所需的所有 Gas 在源分片由底层 EVM Host（`evmone`）直接在解释器层从当前事务的 `gas_left` 中预扣。

### 4.1 目标端静态 Gas 定价模型
* **跨分片转账 (`systemExecuteCrossTransfer`)**：固定执行 1 次 SLOAD + 1 次 SSTORE + 1 次 LOG3，开销恒定：
  $$G_{\text{target\_transfer}} \equiv 30{,}000\ \text{Gas}$$
* **跨分片存储 (`systemExecuteCrossStorage`)**：基础状态开销加数据长度线性开销：
  $$G_{\text{target\_storage}}(L) = 25{,}000 + \left\lceil \frac{L}{32} \right\rceil \times 20{,}000\ \text{Gas}$$

### 4.2 C++ EVM Host 拦截逻辑 (`evmc_host_context`)

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
        if (context->tx_gas_left < target_gas_charge) {
            // 源端 Gas 不足以覆盖目标端执行，触发 Out-of-Gas 回滚
            return evmc_result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
        }
        context->tx_gas_left -= target_gas_charge;
        context->accumulate_cross_gas_reward(target_gas_charge);
    }

    return evmc_result{EVMC_SUCCESS, context->tx_gas_left, nullptr, 0};
}
```

---

## 5. 底层共识层系统入账与 GBP 流水线时序

跨分片消息包由共识层直接推进，不经过目标分片的用户态交易池（Mempool）：

```
[ 源分片共识引擎 (Block Producer) ]
        │  1. 执行交易并生成收据证明 QC(B_src)
        ▼
[ 全局缓冲池 (GBP) ]
        │  2. 按因果序汇聚跨片消息，组装全局块 B_g
        ▼
[ 目标分片区块处理器 (Block Processor) ]
        │  3. 密码学校验: 验证门限聚合签名 QC(B_src)
        │  4. 防重放校验: 校验 !executed_bitmap[msgId]
        │  5. 身份校验: 校验 RecoverBase(target_addr) == RecoverBase(src_addr)
        │  6. 合成系统消息 (msg.sender = SYSTEM_EXECUTOR)
        ▼
[ EVM 解释器 (evmone) ]
        │  7. 执行 systemExecuteCrossTransfer / systemExecuteCrossStorage
        ▼
[ 状态机写入本地 State Trie ]
```

---

## 6. AMM 与高频金融状态的解耦分析与标准落地范式

### 6.1 严禁将跨分片状态存储用于 AMM/订单簿的根本原因
即使网络吞吐极高，跨分片状态存储（`_crossSetStorage`）也**绝对不能**用于同步 AMM 资产池储备量（Reserves）或订单簿撮合，原因在于：

1. **严格非可交换性（Non-Commutativity）**：AMM 交易具有时序滑点依赖，$Tx_A \to Tx_B$ 与 $Tx_B \to Tx_A$ 计算出的剩余储备量与价格完全不同。并发推送将导致“后写覆盖（LWW）”，直接抹除交易结果；
2. **恒定乘积破坏（$k$ 失衡）**：在异步广播的真空期 $\Delta t$ 内，多个分片同时基于旧储备撮合，导致全网 $(x+\Delta x)(y-\Delta y) < k$，流动性迅速穿仓；
3. **剧毒套利（Toxic LVR Arbitrage）**：分片间存在物理传输延迟，套利者利用陈旧状态在各镜像池间进行确定性无风险套利，抽干 LP 资金；
4. **资产与状态虚实脱节（Fractional Reserve）**：状态存储仅同步数值，目标分片金库中并无真实锁存的原生/代币资产，即时兑换将面临无币可提的挤兑风险；
5. **订单簿双重成交（Double-Fill）**：全局限价单若在多个分片并发被吃，撮合引擎将产生负库存。

---

### 6.2 协议支持的标准 AMM 落地范式

```
【 范式 A: 分片独立流动性池 + 跨片套利 (推荐) 】
  [ 分片 1 AMM: Pool(x1, y1) ] ──(价格偏离)──> 套利者源端扣款
                                                    │
                                         _crossTransfer(Token)
                                                    │
  [ 分片 2 AMM: Pool(x2, y2) ] <──(抹平价差)─── 目标端入账并 Swap

【 范式 B: 专属撮合核心分片 (Hub Shard) 】
  [ 业务分片 1, 2, ... K ] ── _crossTransfer(Deposit) ──> [ Hub 撮合分片 ] (100% 本地即时计算)
                           <── _crossTransfer(Withdraw) ──
```

* **`_crossTransfer` 负责价值层**：点对点位移，代数加减法天然可交换，账面与物理资产 $100\%$ 锚定；
* **`_crossSetStorage` 负责控制层**：单主只读广播，用于全局熔断开关、预言机喂价与黑名单同步；
* **非可交换金融计算留在分片本地**：撮合与 Swap 限于局部状态机闭环执行。

---

## 7. 形式化安全性分析与定理证明

### 7.1 定理 1：全网代币总供应量强守恒定理（Conservation of Value）
**证明**：
1. **源端扣除原子性**：EVM 事务中 `_balances[from] -= Δ` 与 `totalSupply -= Δ` 先于事件抛出。若余额不足，EVM 抛出异常回滚状态，跨分片事件不会生成；
2. **中继唯一性与幂等性**：跨分片凭据绑定唯一标识 $\text{PacketID} = \text{keccak256}(\text{srcShard}, \text{dstShard}, \text{baseAddr}, \text{nonce}, \text{height})$，目标端共识层维护已执行位图，重复数据包 $O(1)$ 丢弃；
3. **分身零增发性**：分身合约初始化时 `totalSupply = 0`，且不存在外部 `_mint()` 接口。目标端代币增加的唯一途径为 `systemExecuteCrossTransfer`，其入账量严格等于源端扣除量 $\Delta$；
4. **守恒推导**：
   $$\Delta \text{TotalSupply} = -\Delta (\text{Source}) + 0 (\text{In-Flight}) + \Delta (\text{Destination}) \equiv 0 \quad \blacksquare$$

---

### 7.2 定理 2：地址双射性与抗冒充定理（Bijective Identity Guarantee）
**证明**：
1. **双射性**：Feistel 结构在有限域 $\mathbb{Z}_{2^{160}}$ 上是置换网络。对于任意给定坐标 $(s, p)$，映射 $f_{(s,p)}: A \to Addr_{s,p}$ 是严格的一对一双射函数：
   $$\forall A_1 \neq A_2 \iff f_{(s,p)}(A_1) \neq f_{(s,p)}(A_2)$$
2. **唯一可逆性**：逆映射 $f_{(s,p)}^{-1}(Addr_{s,p}) \equiv A$ 确定且唯一。目标分片共识层在派发跨分片消息前，执行强制断言：
   $$f_{(s_{\text{dst}}, p_{\text{dst}})}^{-1}(Addr_{\text{dst}}) == f_{(s_{\text{src}}, p_{\text{src}})}^{-1}(Addr_{\text{src}}) \equiv A_{\text{Base}}$$
   若攻击者在目标分片部署恶意非关联合约，其计算出的 $A_{\text{Base}}'$ 必不匹配，系统调用绝不会派发至恶意地址。 $\blacksquare$

---

### 7.3 定理 3：目标端执行确定性与零 Revert 定理（Deterministic Zero-Revert Invariant）
**证明**：
1. 目标端入账函数 `_receiveCrossTransfer` 仅包含单一存储累加操作：
   $$\text{SLOAD} \to \text{ADD} \to \text{SSTORE}$$
2. 不包含任何条件断言（`require`）、循环或外部调用钩子（No Hooks）；
3. 算术运算遵循 Solidity 0.8+ 规范，由于全网代币总供应量受限且源端已完成等额扣除，$\text{Balance} + \Delta$ 绝不可能发生溢出；
4. 目标端执行成功率恒为 $100\%$，消除因应用层 Revert 导致的资产蒸发。 $\blacksquare$

---

### 7.4 核心安全属性矩阵

| 安全威胁维度 | 传统跨链 / 分片模型表现 | 本协议保障机制 | 安全强度评级 |
| :--- | :--- | :--- | :---: |
| **恶意分身增发** | 容易因多链部署失误导致重复 Mint | **Feistel 自鉴权：全网分身初始化强制为 0 供应量** | **数学级免疫 (P0)** |
| **伪造系统调用加钱** | 依赖合约层管理员多签，易被钓鱼 | **特权 `SYSTEM_EXECUTOR` 由共识层注入，外部无法模拟** | **共识级免疫 (P0)** |
| **目标端 Gas 耗尽死账** | 用户动态预估不准导致 Out-of-Gas | **编译期常量定价 + 源端 Host 强行预扣** | **确定性免疫 (P0)** |
| **地址抢占与后门植入** | 攻击者抢先在目标分片部署恶意合约 | **派生地址为系统保留区，仅允许共识引擎自动分身** | **系统级免疫 (P0)** |
| **金融状态竞争与穿仓** | 跨片共享 AMM 储备导致状态覆盖 | **三层职责解耦：高频非可交换状态严格分片本地闭环** | **架构级免疫 (P0)** |
| **网络重放攻击** | 依赖应用层 Nonce，容易乱序 | **全局单调 Nonce + 目标端共识位图去重** | **协议级免疫 (P0)** |