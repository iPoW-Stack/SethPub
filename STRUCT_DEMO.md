# Solidity 结构体演示文档

## 概述

`StructDemo` 是一个完整的 Solidity 智能合约示例，展示了如何在 Seth 区块链上使用结构体作为函数参数和返回值。

## 位置

- **合约代码**: `clipy/seth3.py` (Lines 199-450)
- **测试函数**: `clipy/seth3.py` (Lines 545-850)
- **调用位置**: `ecdsa_sign_test()` 函数中

## 核心特性

### 1. 结构体定义

```solidity
struct UserInfo {
    address userAddr;        // 用户地址
    string name;             // 用户名
    uint256 balance;         // 账户余额
    uint256 joinTime;        // 加入时间
    bool isActive;           // 是否活跃
}

struct Transaction {
    address from;            // 发送者
    address to;              // 接收者
    uint256 amount;          // 交易金额
    uint256 timestamp;       // 交易时间
    string txType;           // 交易类型
    bool success;            // 是否成功
}

struct AccountStats {
    uint256 totalTransactions;  // 总交易数
    uint256 totalIn;            // 总收入
    uint256 totalOut;           // 总支出
    uint256 lastTxTime;         // 最后交易时间
    uint256 averageAmount;      // 平均交易额
}
```

### 2. 结构体作为参数

#### 2.1 单个结构体参数

```solidity
function registerUser(UserInfo calldata info) 
    external 
    returns (bool success)
```

**使用示例**:
```python
# 在 Python 中调用
user_info = (
    "0x1234567890123456789012345678901234567890",  # userAddr
    "Alice",                                          # name
    1000,                                             # balance
    0,                                                # joinTime (自动设置)
    True                                              # isActive
)
tx = struct_contract.functions.registerUser(user_info).transact(KEY)
```

#### 2.2 结构体参数和返回值

```solidity
function executeTransaction(Transaction calldata tx) 
    external 
    payable 
    returns (bool success)
```

**特点**:
- 接收 `Transaction` 结构体作为参数
- 验证结构体字段
- 返回布尔值表示执行结果

#### 2.3 结构体数组

```solidity
function batchExecute(Transaction[] calldata txs) 
    external 
    returns (uint256 successCount)
```

**功能**:
- 接收多个 `Transaction` 结构体
- 循环处理每个交易
- 返回成功的交易数量

### 3. 结构体作为返回值

#### 3.1 返回单个结构体

```solidity
function getUserInfo(address userAddr) 
    external 
    view 
    returns (UserInfo memory)
```

**特点**:
- 返回完整的 `UserInfo` 结构体
- 前端/调用者可以直接访问所有字段

#### 3.2 返回结构体数组

```solidity
function getTransactionHistory(address userAddr) 
    external 
    view 
    returns (Transaction[] memory)
```

**应用**:
- 获取用户的所有交易历史
- 支持分页查询
- 支持过滤查询

#### 3.3 返回多个结构体（元组）

```solidity
function getUserFullInfo(address userAddr) 
    external 
    view 
    returns (UserInfo memory, AccountStats memory, uint256)
```

**特点**:
- 返回多个不同类型
- 包括两个结构体和一个 uint256
- 调用者接收完整数据元组

#### 3.4 返回计算的结构体

```solidity
function getAccountStats(address userAddr) 
    external 
    view 
    returns (AccountStats memory)
```

**功能**:
- 根据交易历史计算统计信息
- 返回包含计算结果的结构体

## ABI 编码

### 结构体参数编码

当结构体作为参数时，Solidity ABI 会自动将其编码为元组:

```
struct UserInfo {
    address userAddr;
    string name;
    uint256 balance;
    uint256 joinTime;
    bool isActive;
}

↓ ABI 编码 ↓

(address, string, uint256, uint256, bool)
```

### Python 调用示例

```python
# 创建结构体数据（作为元组）
user_info = (
    "0x1234567890123456789012345678901234567890",  # address
    "Alice",                                          # string
    1000,                                             # uint256
    0,                                                # uint256  
    True                                              # bool
)

# 调用函数
tx = struct_contract.functions.registerUser(user_info).transact(KEY)

# 获取返回值
result = struct_contract.functions.getUserInfo("0x1234...").call()

# result 是一个元组，可以这样访问:
# result[0] - userAddr
# result[1] - name
# result[2] - balance
# result[3] - joinTime
# result[4] - isActive

# 或者使用属性访问 (取决于 web3.py 版本):
# result.userAddr
# result.name
# result.balance
```

## 测试场景

`test_struct_demo()` 函数包含 9 个完整的测试场景:

### 场景 1: 部署合约

```python
struct_bin, struct_abi = compile_and_link(STRUCT_DEMO_SOL, "StructDemo")
struct_contract = w3.seth.contract(abi=struct_abi, bytecode=struct_bin).deploy({
    'from': MY,
    'salt': RANDOM_SALT + 'struct_demo',
}, KEY)
```

### 场景 2: 传入结构体参数

```python
# registerUser() - 接收 UserInfo 结构体参数
user_info = (MY, "Alice", 1000, 0, True)
tx = struct_contract.functions.registerUser(user_info).transact(KEY)
```

### 场景 3: 返回结构体

```python
# getUserInfo() - 返回 UserInfo 结构体
result = struct_contract.functions.getUserInfo(MY).call()
# result = (address, string, uint256, uint256, bool)
```

### 场景 4: 结构体参数 + 返回

```python
# executeTransaction() - 接收 Transaction 参数，返回 bool
tx_data = (MY, target_addr, 100, 0, "transfer", True)
success = struct_contract.functions.executeTransaction(tx_data).transact(KEY)
```

### 场景 5: 返回结构体数组

```python
# getTransactionHistory() - 返回 Transaction[] 
history = struct_contract.functions.getTransactionHistory(MY).call()
# history = [(addr, addr, uint256, ...), (addr, addr, uint256, ...), ...]
```

### 场景 6: 返回多个结构体（元组）

```python
# getUserFullInfo() - 返回 (UserInfo, AccountStats, uint256)
user_info, stats, tx_count = struct_contract.functions.getUserFullInfo(MY).call()
```

### 场景 7: 返回计算的结构体

```python
# getAccountStats() - 返回 AccountStats 结构体
stats = struct_contract.functions.getAccountStats(MY).call()
# stats 包含计算的统计数据
```

### 场景 8: 过滤的结构体数组返回

```python
# searchTransactions() - 基于金额范围返回过滤后的交易数组
results = struct_contract.functions.searchTransactions(MY, 50, 150).call()
```

### 场景 9: 批量处理结构体数组

```python
# batchExecute() - 处理多个 Transaction 结构体
tx_list = [
    (MY, addr1, 100, 0, "transfer", True),
    (MY, addr2, 200, 0, "swap", True),
]
success_count = struct_contract.functions.batchExecute(tx_list).transact(KEY)
```

## 关键概念

### 1. Calldata vs Memory

- **calldata**: 用于函数参数，节省 gas，不能修改
- **memory**: 用于返回值或临时变量，可以修改

```solidity
// Calldata 用于输入参数
function registerUser(UserInfo calldata info) external returns (bool) { ... }

// Memory 用于返回值
function getUserInfo(address userAddr) external view returns (UserInfo memory) { ... }
```

### 2. 结构体字段访问

```solidity
// 访问参数中的结构体字段
function registerUser(UserInfo calldata info) external {
    address addr = info.userAddr;     // ✅ 直接访问
    string memory name = info.name;   // ✅ 复制到内存
}

// 访问状态变量中的结构体字段
function getBalance(address user) external view returns (uint256) {
    return users[user].balance;  // ✅ 直接访问存储
}
```

### 3. 事件中使用结构体

```solidity
// 事件可以包含结构体字段
event UserRegistered(
    address indexed userAddr,
    string name,
    uint256 joinTime
);

// 发出事件
emit UserRegistered(info.userAddr, info.name, block.timestamp);
```

## 最佳实践

### 1. 参数验证

```solidity
function registerUser(UserInfo calldata info) external returns (bool) {
    require(info.userAddr != address(0), "Invalid address");
    require(bytes(info.name).length > 0, "Name cannot be empty");
    require(info.balance >= 0, "Balance cannot be negative");
    // ...
}
```

### 2. 结构体初始化

```solidity
UserInfo memory newUser = UserInfo({
    userAddr: info.userAddr,
    name: info.name,
    balance: info.balance,
    joinTime: block.timestamp,
    isActive: true
});
```

### 3. 返回值处理

```python
# Python 中处理返回的结构体
result = contract.functions.getUserInfo(address).call()

# 方法 1: 元组索引访问
user_addr = result[0]
user_name = result[1]
balance = result[2]

# 方法 2: 命名元组访问 (如果 web3.py 返回命名元组)
user_addr = result.userAddr
user_name = result.name
balance = result.balance
```

## 常见问题

### Q1: 结构体能作为状态变量吗？

**A**: 是的，可以！

```solidity
struct UserInfo { ... }

// ✅ 这些都是有效的
UserInfo public user;                    // 单个结构体
mapping(address => UserInfo) public users;  // 结构体映射
UserInfo[] public userList;              // 结构体数组
```

### Q2: 结构体的 gas 成本如何？

**A**: 
- 结构体字段通常作为单独的存储槽
- 不同的字段类型影响 gas 成本
- 使用 `calldata` 参数比 `memory` 更便宜

### Q3: 能否嵌套结构体？

**A**: 是的！

```solidity
struct Address {
    string city;
    string country;
}

struct User {
    string name;
    Address address;  // ✅ 嵌套结构体
}
```

### Q4: 能否在结构体中使用数组？

**A**: 是的！

```solidity
struct TransactionBatch {
    address[] participants;  // ✅ 动态数组
    uint256[10] amounts;     // ✅ 固定大小数组
}
```

## 集成信息

### 代码位置

| 组件 | 位置 | 行数 |
|------|------|------|
| StructDemo 合约 | `clipy/seth3.py` | 199-450 |
| test_struct_demo() 函数 | `clipy/seth3.py` | 545-850 |
| ecdsa_sign_test() 调用 | `clipy/seth3.py` | 1788 |
| __main__ 块 | `clipy/seth3.py` | 2303-2308 |

### 执行方式

```bash
# 运行完整测试套件（包括结构体演示）
python clipy/seth3.py

# 或在 Python 中直接调用
from seth_sdk import SethWeb3Mock
w3 = SethWeb3Mock("127.0.0.1", 23001)
MY = w3.client.get_address(KEY)
test_struct_demo(w3, MY, KEY)
```

## 相关文档

- [SETH 快速参考](QUICK_REFERENCE.md)
- [相同分片原子性设计](SAME_SHARD_ATOMICITY_DESIGN.md)
- [AMM 原子交换演示](SAME_SHARD_ATOMICITY_DESIGN.md)

## 总结

StructDemo 展示了 Solidity 中结构体的强大功能：

✅ **参数**: 作为函数参数接收复杂数据  
✅ **返回值**: 作为返回值返回多个相关数据  
✅ **存储**: 在状态变量中存储结构化数据  
✅ **数组**: 管理结构体集合  
✅ **编码**: 自动 ABI 编码/解码  

这使开发者能够编写更清晰、更易维护的智能合约代码。
