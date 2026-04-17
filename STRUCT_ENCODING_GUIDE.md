# Solidity 结构体 ABI 编码详细指南

## 目录

1. [基础概念](#基础概念)
2. [结构体到元组的转换](#结构体到元组的转换)
3. [编码规则](#编码规则)
4. [实际示例](#实际示例)
5. [Python 交互指南](#python-交互指南)
6. [常见陷阱](#常见陷阱)

## 基础概念

### 什么是 ABI？

ABI (Application Binary Interface) 定义了智能合约与外界通信的方式。当 Solidity 编译器编译合约时，会生成一个 JSON ABI 文件，描述所有公开的函数和它们的参数类型。

### 结构体在 ABI 中如何表示？

在 ABI 中，结构体被表示为**元组** (tuple)，其字段成为元组的各个组件。

```solidity
struct UserInfo {
    address userAddr;
    string name;
    uint256 balance;
    bool isActive;
}
```

对应的 ABI 表示：

```json
{
  "components": [
    { "name": "userAddr", "type": "address" },
    { "name": "name", "type": "string" },
    { "name": "balance", "type": "uint256" },
    { "name": "isActive", "type": "bool" }
  ],
  "name": "info",
  "type": "tuple"
}
```

## 结构体到元组的转换

### 转换规则

| 结构体声明 | Python 表示 | 说明 |
|----------|-----------|------|
| `struct S { address a; }` | `(address,)` 或 `(address_value,)` | 单字段 |
| `struct S { address a; uint256 b; }` | `(address_value, uint256_value)` | 多字段按顺序 |
| `struct S { string s; bytes data; }` | `("hello", b"data")` | 动态类型 |

### 基本类型对应

```python
# Solidity Type → Python Type

address         → str (20字节十六进制)
uint256, uint   → int
uint8-uint255   → int
bool            → bool
string          → str
bytes           → bytes
bytes32         → bytes
address[]       → list[str]
uint256[]       → list[int]
```

## 编码规则

### 1. 字段顺序必须精确匹配

```solidity
struct User {
    address addr;      // 第 0 位
    string name;       // 第 1 位
    uint256 balance;   // 第 2 位
}
```

**正确的 Python 调用**:
```python
# 顺序匹配：addr, name, balance
user_data = ("0x123...", "Alice", 1000)
contract.functions.register(user_data).transact(KEY)
```

**错误的调用** ❌:
```python
# 顺序错误！
user_data = ("Alice", "0x123...", 1000)  # ❌ 会编码错误
contract.functions.register(user_data).transact(KEY)
```

### 2. 类型必须精确匹配

```solidity
struct Data {
    uint256 num;       // uint256 类型
    uint8 small;       // uint8 类型
}
```

**正确** ✅:
```python
data = (1000, 255)  # 第一个字段用 int，第二个也用 int
contract.functions.sendData(data).transact(KEY)
```

**问题** ⚠️:
```python
data = (1000.5, 255)  # ❌ uint256 不接受浮点数
contract.functions.sendData(data).transact(KEY)
```

### 3. 地址格式

```python
# 有效的地址格式
from eth_utils import to_checksum_address

address1 = "0x1234567890123456789012345678901234567890"
address2 = to_checksum_address("0x1234567890123456789012345678901234567890")

# 两者都有效，但建议使用 checksum 格式
struct_data = (address2, "name", 100, True)
```

### 4. 字符串和字节

```solidity
struct Content {
    string text;       // 动态字符串
    bytes data;        // 动态字节
    bytes32 hash;      // 固定32字节
}
```

**Python 编码**:
```python
# 正确的编码方式
content = (
    "Hello World",          # string
    b"binary_data",         # bytes
    b"0x" + b"00"*32        # bytes32
)

# bytes32 也可以这样
content = (
    "Hello World",
    b"binary_data",
    bytes.fromhex("00" * 64)  # 32 字节
)
```

## 实际示例

### 示例 1: 简单结构体

```solidity
struct Point {
    uint256 x;
    uint256 y;
}

function setPoint(Point memory p) external {
    // ...
}
```

**Python 调用**:
```python
point = (100, 200)  # (x=100, y=200)
contract.functions.setPoint(point).transact(KEY)
```

**调用流程**:
```
Python: point = (100, 200)
  ↓
ABI 编码: [0x64, 0xc8]  (100和200的十六进制)
  ↓
Solidity: p.x = 100, p.y = 200
```

### 示例 2: 复杂结构体

```solidity
struct Transaction {
    address from;
    address to;
    uint256 amount;
    string description;
    bool approved;
}

function executeTransaction(Transaction calldata tx) external {
    // ...
}
```

**Python 调用**:
```python
tx = (
    "0x1111111111111111111111111111111111111111",  # from (address)
    "0x2222222222222222222222222222222222222222",  # to (address)
    500,                                           # amount (uint256)
    "Payment for services",                        # description (string)
    True                                           # approved (bool)
)

contract.functions.executeTransaction(tx).transact(KEY)
```

### 示例 3: 结构体数组

```solidity
struct Record {
    uint256 id;
    string label;
}

function batchStore(Record[] calldata records) external {
    // ...
}
```

**Python 调用**:
```python
records = [
    (1, "First"),
    (2, "Second"),
    (3, "Third"),
]

contract.functions.batchStore(records).transact(KEY)
```

### 示例 4: 返回结构体

```solidity
struct Result {
    bool success;
    uint256 value;
    string message;
}

function compute() external view returns (Result memory) {
    // ...
}
```

**Python 调用和返回值处理**:
```python
# 调用函数
result = contract.functions.compute().call()

# result 是一个元组: (success, value, message)

# 方法 1: 按索引访问
success = result[0]
value = result[1]
message = result[2]

# 方法 2: 如果 web3.py 返回命名元组
success = result.success
value = result.value
message = result.message

# 方法 3: 解包
success, value, message = result
```

## Python 交互指南

### 1. 构建结构体数据

```python
from eth_utils import to_checksum_address

# 方法 1: 直接元组
user = (
    to_checksum_address("0x1234..."),
    "Alice",
    1000,
    True
)

# 方法 2: 字典（如果库支持）
user = {
    "userAddr": to_checksum_address("0x1234..."),
    "name": "Alice",
    "balance": 1000,
    "isActive": True
}

# 方法 3: 自定义类
class User:
    def __init__(self, addr, name, balance, is_active):
        self.userAddr = to_checksum_address(addr)
        self.name = name
        self.balance = balance
        self.isActive = is_active
    
    def to_tuple(self):
        return (self.userAddr, self.name, self.balance, self.isActive)

user_obj = User("0x1234...", "Alice", 1000, True)
contract.functions.register(user_obj.to_tuple()).transact(KEY)
```

### 2. 处理返回的结构体

```python
# 获取返回值
result = contract.functions.getUserInfo(address).call()

# 根据类型处理
if isinstance(result, tuple):
    # 元组形式
    user_addr, name, balance, active = result
elif isinstance(result, dict):
    # 字典形式（某些版本的 web3.py）
    user_addr = result['userAddr']
    name = result['name']
    balance = result['balance']
    active = result['isActive']

# 打印结果
print(f"用户: {name}")
print(f"地址: {user_addr}")
print(f"余额: {balance}")
print(f"活跃: {active}")
```

### 3. 处理结构体数组

```python
# 获取结构体数组
transactions = contract.functions.getTransactionHistory(user_addr).call()

# 迭代处理
for tx in transactions:
    print(f"From: {tx[0]}")
    print(f"To: {tx[1]}")
    print(f"Amount: {tx[2]}")
    print(f"---")

# 或者
for i, tx in enumerate(transactions):
    from_addr, to_addr, amount = tx[0], tx[1], tx[2]
    print(f"Transaction {i}: {from_addr} -> {to_addr}, Amount: {amount}")
```

### 4. 使用事件解析结构体数据

```python
# 监听事件
event_filter = contract.events.UserRegistered.create_filter(from_block='latest')

# 处理事件
for event in event_filter.get_new_entries():
    user_addr = event['args']['userAddr']
    name = event['args']['name']
    join_time = event['args']['joinTime']
    print(f"New user: {name} ({user_addr}) at {join_time}")
```

## 常见陷阱

### 陷阱 1: 字段顺序错误

❌ **错误**:
```python
# 结构体定义: { name, addr, balance }
# 但你这样调用: { addr, name, balance }
data = (to_checksum_address("0x123..."), "Alice", 1000)  # ❌ 顺序错
```

✅ **正确**:
```python
# 必须按 Solidity 中的顺序
data = ("Alice", to_checksum_address("0x123..."), 1000)  # ✅ 顺序对
```

### 陷阱 2: 类型不匹配

❌ **错误**:
```python
# uint256 需要整数
data = (3.14, "text", True)  # ❌ 浮点数不对
```

✅ **正确**:
```python
data = (3, "text", True)  # ✅ 整数
```

### 陷阱 3: 地址格式

❌ **错误**:
```python
# 地址需要完整的 40 字符（20 字节）
data = ("0x123", "name", 100)  # ❌ 地址太短
```

✅ **正确**:
```python
from eth_utils import to_checksum_address
data = (to_checksum_address("0x1234567890123456789012345678901234567890"), 
        "name", 100)  # ✅ 完整地址
```

### 陷阱 4: 动态类型编码

❌ **错误**:
```python
# 字符串是动态类型，不能直接作为字节
data = ("hello", b"world")  # ⚠️ "hello" 应该是字符串，不是字节
```

✅ **正确**:
```python
data = ("hello", b"world")  # ✅ 第一个是字符串，第二个是字节
# 或者
data = (b"hello", b"world")  # ✅ 都是字节
```

### 陷阱 5: 返回值解包

❌ **错误**:
```python
# 忽略了元组中的元素
result = contract.functions.getUser().call()
user_addr = result  # ❌ result 是元组，不是单个值
```

✅ **正确**:
```python
result = contract.functions.getUser().call()
user_addr, name, balance = result  # ✅ 正确解包
# 或
user_addr = result[0]  # ✅ 按索引访问
name = result[1]
balance = result[2]
```

## 调试技巧

### 1. 打印 ABI 结构

```python
import json

# 获取合约 ABI
abi = contract.abi

# 找到特定函数
for func in abi:
    if func['name'] == 'register':
        print(json.dumps(func, indent=2))
        # 会显示参数的完整结构
```

### 2. 验证数据结构

```python
# 创建数据之前检查字段
def validate_user_struct(data):
    """验证用户结构体"""
    if not isinstance(data, tuple) or len(data) != 4:
        raise ValueError("Expected tuple of 4 elements")
    
    addr, name, balance, active = data
    
    # 验证类型
    if not isinstance(addr, str) or len(addr) != 42:
        raise ValueError("Invalid address format")
    if not isinstance(name, str):
        raise ValueError("Name must be string")
    if not isinstance(balance, int):
        raise ValueError("Balance must be integer")
    if not isinstance(active, bool):
        raise ValueError("Active must be boolean")
    
    return True

# 使用
user_data = (to_checksum_address("0x123..."), "Alice", 1000, True)
if validate_user_struct(user_data):
    contract.functions.register(user_data).transact(KEY)
```

### 3. 使用日志记录

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 记录结构体数据
logger.debug(f"Sending struct: {user_data}")
logger.debug(f"Struct types: {[type(x).__name__ for x in user_data]}")

# 记录返回值
result = contract.functions.getUser().call()
logger.debug(f"Received result: {result}")
logger.debug(f"Result types: {[type(x).__name__ for x in result]}")
```

## 总结

| 操作 | 关键点 |
|------|-------|
| **传入结构体** | 按 Solidity 中的字段顺序构建元组 |
| **访问字段** | 使用索引 `result[i]` 或属性 `result.fieldname` |
| **返回值** | 返回的是元组，需要解包或按索引访问 |
| **类型转换** | 使用 `to_checksum_address()` 转换地址 |
| **验证** | 在编码前验证数据类型和顺序 |
| **调试** | 使用 ABI 检查和日志记录 |

## 相关资源

- [Solidity 文档 - 结构体](https://docs.soliditylang.org/en/latest/types.html#structs)
- [Solidity ABI 编码](https://docs.soliditylang.org/en/latest/abi-spec.html)
- [web3.py 文档](https://web3py.readthedocs.io/)
- [STRUCT_DEMO.md](STRUCT_DEMO.md) - 实际演示
