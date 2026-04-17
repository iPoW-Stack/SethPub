# Solidity 结构体快速参考卡

## 🎯 一页纸速查表

### 结构体定义模板

```solidity
struct MyStruct {
    address field1;      // 地址类型
    uint256 field2;      // 数字类型
    string field3;       // 字符串类型
    bool field4;         // 布尔类型
}
```

### 参数传递

```solidity
// 接收结构体参数
function process(MyStruct calldata data) external {
    address f1 = data.field1;
    uint256 f2 = data.field2;
    // ...
}
```

**Python 调用**:
```python
data = (address, 1000, "text", True)
contract.functions.process(data).transact(KEY)
```

### 返回结构体

```solidity
// 返回结构体
function getData() external view returns (MyStruct memory) {
    return MyStruct({
        field1: msg.sender,
        field2: 1000,
        field3: "data",
        field4: true
    });
}
```

**Python 接收**:
```python
result = contract.functions.getData().call()
# result = (address, 1000, "data", True)

# 访问字段
addr = result[0]
val = result[1]
```

### 存储结构体

```solidity
mapping(address => MyStruct) public items;

function save(address key, MyStruct calldata data) external {
    items[key] = data;
}

function load(address key) external view returns (MyStruct memory) {
    return items[key];
}
```

### 结构体数组

```solidity
MyStruct[] public array;

function addBatch(MyStruct[] calldata batch) external {
    for (uint i = 0; i < batch.length; i++) {
        array.push(batch[i]);
    }
}

function getAll() external view returns (MyStruct[] memory) {
    return array;
}
```

**Python**:
```python
# 发送数组
batch = [(addr1, 100, "a", True), (addr2, 200, "b", False)]
contract.functions.addBatch(batch).transact(KEY)

# 接收数组
results = contract.functions.getAll().call()
for item in results:
    print(item[0], item[1], item[2], item[3])
```

---

## 🔑 关键规则

| 规则 | 说明 | 错误示例 |
|------|------|---------|
| **顺序** | 字段必须按 Solidity 顺序 | ❌ (name, addr, val) 当应该 (addr, name, val) |
| **类型** | Python 类型要匹配 Solidity | ❌ "123" 当应该 123 (uint) |
| **地址** | 使用完整 40 字符十六进制 | ❌ "0x123" (只有 3 字符) |
| **字符串** | Python str 对应 Solidity string | ❌ b"text" 当应该 "text" |

---

## 🧪 常见操作

### 单个结构体

```python
# 创建
data = (address, 100, "text", True)

# 发送
tx = contract.functions.send(data).transact(KEY)

# 接收
result = contract.functions.get().call()

# 访问
value = result[1]
```

### 结构体数组

```python
# 创建
array = [
    (addr1, 100, "a", True),
    (addr2, 200, "b", False),
]

# 发送
tx = contract.functions.sendArray(array).transact(KEY)

# 接收
results = contract.functions.getArray().call()

# 迭代
for item in results:
    print(item)
```

### 多个返回值 (元组)

```python
# Solidity 返回 (S1, S2, uint256)
user, stats, count = contract.functions.getFullInfo().call()

# 访问每个结构体
user_addr = user[0]
user_name = user[1]

stat_total = stats[0]
stat_in = stats[1]
```

---

## ⚠️ 常见陷阱

### 陷阱 1: 字段顺序错误
❌ 错误:
```python
# 结构体: {name, address, balance}
data = (address_val, "Alice", 100)  # 顺序错
```

✅ 正确:
```python
data = ("Alice", address_val, 100)  # 顺序对
```

### 陷阱 2: 类型不匹配
❌ 错误:
```python
# uint256 需要整数
data = (address, 3.14, "text", True)  # 浮点数
```

✅ 正确:
```python
data = (address, 3, "text", True)  # 整数
```

### 陷阱 3: 地址不完整
❌ 错误:
```python
# 地址必须 40 字符
data = ("0x123", "text", 100)  # 太短
```

✅ 正确:
```python
data = ("0x" + "0"*39 + "123", "text", 100)  # 40 字符
```

### 陷阱 4: 返回值处理
❌ 错误:
```python
result = contract.functions.get().call()
addr = result  # result 是元组，不是单个值
```

✅ 正确:
```python
result = contract.functions.get().call()
addr = result[0]  # 按索引访问
```

---

## 🔧 调试技巧

### 1. 验证数据类型
```python
# 发送前检查
data = (address, 100, "text", True)
print([type(x).__name__ for x in data])
# 输出: ['str', 'int', 'str', 'bool']
```

### 2. 打印 ABI 结构
```python
import json
for func in contract.abi:
    if func['name'] == 'myFunction':
        print(json.dumps(func, indent=2))
```

### 3. 查看返回值
```python
result = contract.functions.getData().call()
print(f"返回值: {result}")
print(f"类型: {type(result)}")
print(f"长度: {len(result)}")

# 逐个显示
for i, item in enumerate(result):
    print(f"  [{i}] = {item} ({type(item).__name__})")
```

### 4. 事件日志追踪
```python
# 监听事件获取结构体数据
events = contract.events.MyEvent.get_logs()
for event in events:
    struct_data = event['args']['data']
    print(f"事件: {struct_data}")
```

---

## 📊 性能对比

### Calldata vs Memory

| 特性 | Calldata | Memory |
|------|----------|--------|
| 用途 | 函数参数 | 返回值/临时 |
| Gas | 便宜 | 较贵 |
| 修改 | 不能 | 可以 |
| 存储 | 交易数据 | 运行时 |

### 结构体打包 Gas 节省

```solidity
// 非优化 (3 个存储槽)
struct Unpacked {
    uint256 a;  // 1 槽
    uint256 b;  // 1 槽
    address c;  // 1 槽
}

// 优化 (1 个存储槽)
struct Packed {
    uint96 a;   // 96 bits
    uint96 b;   // 96 bits
    address c;  // 160 bits = 20 字节
}

// 节省: 66% 的存储
```

---

## 🚀 3 分钟上手

### 第 1 步: 定义结构体 (30 秒)
```solidity
struct User {
    address addr;
    string name;
    uint256 balance;
}
```

### 第 2 步: 编写函数 (1 分钟)
```solidity
function registerUser(User calldata u) external {
    users[u.addr] = u;
}

function getUser(address addr) external view returns (User memory) {
    return users[addr];
}
```

### 第 3 步: 调用函数 (1 分钟 30 秒)
```python
# 发送
user = ("0x123...", "Alice", 1000)
contract.functions.registerUser(user).transact(KEY)

# 接收
result = contract.functions.getUser("0x123...").call()
print(result)  # ("0x123...", "Alice", 1000)
```

---

## 📚 完整文档

| 文档 | 用途 | 阅读时间 |
|------|------|--------|
| [STRUCT_DEMO.md](STRUCT_DEMO.md) | 完整指南 + 示例 | 15 分钟 |
| [STRUCT_ENCODING_GUIDE.md](STRUCT_ENCODING_GUIDE.md) | 深度讲解 + 调试 | 30 分钟 |
| 本文档 | 快速参考 | 5 分钟 |

---

## ❓ FAQ

**Q: 结构体能嵌套吗？**  
A: 是的。`struct A { B inner; }` 其中 B 是另一个结构体。

**Q: 能有动态数组吗？**  
A: 是的。`struct S { uint[] arr; }`

**Q: Gas 成本如何？**  
A: 取决于字段数和大小。使用打包优化可以节省 50-70%。

**Q: 能用在映射中吗？**  
A: 是的。`mapping(address => MyStruct) public data;`

**Q: 返回 memory 和 storage 的区别？**  
A: memory 是一份副本，storage 是原始数据。view 函数返回 memory。

---

**版本**: 1.0  
**日期**: 2024-04-17  
**相关**: Phase 4 结构体演示

---

## 🎯 下一步

1. **快速上手**: 按"3 分钟上手"部分实现
2. **详细学习**: 阅读 [STRUCT_DEMO.md](STRUCT_DEMO.md)
3. **深度理解**: 学习 [STRUCT_ENCODING_GUIDE.md](STRUCT_ENCODING_GUIDE.md)
4. **查看代码**: 打开 `clipy/seth3.py` 查看完整实现
5. **运行测试**: 执行 `python clipy/seth3.py` 验证

**准备好了吗？开始吧！** 🚀
