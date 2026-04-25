# 运行 EIP-1559 测试

## 前提条件

确保已安装所需的 Python 依赖：

```bash
pip install eth-account eth-utils eth-abi pycryptodome ecdsa
```

## 运行测试

### 方法 1: 使用默认配置

```bash
cd /root/seth/clipy
python3 test_eip1559.py
```

### 方法 2: 指定自定义配置

```bash
cd /root/seth/clipy
python3 test_eip1559.py --host 192.168.1.100 --port 8545 --key <your_private_key>
```

### 方法 3: 运行简单示例

```bash
cd /root/seth/clipy
python3 eip1559_example.py
```

## 默认配置

- **Host**: 127.0.0.1
- **Port**: 23001
- **Private Key**: 71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6

## 故障排除

### 问题 1: ModuleNotFoundError

如果遇到 `ModuleNotFoundError: No module named 'eth_utils'` 等错误，请安装依赖：

```bash
pip install eth-account eth-utils eth-abi pycryptodome ecdsa
```

### 问题 2: 找不到 seth3 模块

确保在 `clipy` 目录下运行脚本：

```bash
cd /root/seth/clipy
python3 test_eip1559.py
```

### 问题 3: 连接失败

确保 Seth 节点正在运行并监听正确的端口：

```bash
# 检查节点是否运行
ps aux | grep seth

# 检查端口是否开放
netstat -an | grep 23001
```

## 预期输出

成功运行时，您应该看到类似以下的输出：

```
======================================================================
EIP-1559 Transaction Test Suite
======================================================================
Host: 127.0.0.1:23001
Private Key: 71e57186...8e73b2f6
Sender Address: 620a1c023fdef21f3c10bf3d468de37d5ecfdc7b
Sender Balance: 1000000000

======================================================================
TEST CASE 1: EIP-1559 Native Token Transfer
======================================================================
[1] Preparing EIP-1559 transfer...
    ✅ Transaction sent!
[2] Waiting for transaction confirmation...
    ✅ Transaction confirmed!

...

======================================================================
TEST SUMMARY
======================================================================
EIP-1559 Transfer................................ ✅ PASSED
EIP-1559 Contract Deploy......................... ✅ PASSED
EIP-1559 Contract Call........................... ✅ PASSED

Total: 3/3 tests passed
🎉 All tests passed!
```

## 获取帮助

```bash
python3 test_eip1559.py --help
```

输出：
```
usage: test_eip1559.py [-h] [--host HOST] [--port PORT] [--key KEY]

EIP-1559 Transaction Test

optional arguments:
  -h, --help   show this help message and exit
  --host HOST  Seth node host (default: 127.0.0.1)
  --port PORT  Seth node port (default: 23001)
  --key KEY    Private key (hex, default: test key)
```
