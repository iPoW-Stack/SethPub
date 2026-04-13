# HTTP Handler 迁移到 uWebSockets + HTTPS

## 概述

本次更新将 `http_handler` 从 `httplib` 库迁移到 `uWebSockets` 库，并启用了 HTTPS 支持，使用自签名证书。

## 主要变更

### 1. 库替换
- **旧库**: cpp-httplib
- **新库**: uWebSockets (高性能 WebSocket 和 HTTP 服务器库)

### 2. HTTPS 支持
- 使用 OpenSSL 生成自签名证书
- 证书文件: `server-cert.pem`
- 私钥文件: `server-key.pem`

### 3. 文件变更

#### 新增文件
- `src/init/uws_adapter.h` - 适配器类，使 uWebSockets 兼容原有的 httplib 风格代码
  - `UWSRequest` - 请求包装类
  - `UWSResponse` - 响应包装类

#### 修改文件
- `src/init/http_handler.h`
  - 移除 httplib 依赖
  - 添加 uWebSockets (App.h) 依赖
  - 添加证书文件路径成员变量
  - 添加运行状态标志

- `src/init/http_handler.cc`
  - 所有 `httplib::Request` 替换为 `UWSRequest`
  - 所有 `httplib::Response` 替换为 `UWSResponse`
  - 重写 `Run()` 方法使用 `uWS::SSLApp`
  - 重写 `Init()` 方法配置 HTTPS

- `CMakeLists.txt`
  - 添加 uWebSockets 头文件路径
  - 添加链接库: `uSockets`, `z`, `ssl`, `crypto`

### 4. 证书生成

使用以下命令生成自签名证书（已执行）:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"
```

## API 端点

所有原有的 HTTP POST 端点保持不变，现在通过 HTTPS 访问：

- `/transaction` - 标准交易
- `/oqs_transaction` - OQS 量子安全交易
- `/gm_transaction` - 国密交易
- `/query_contract` - 查询合约
- `/abi_query_contract` - ABI 查询合约
- `/query_account` - 查询账户
- `/query_init` - 初始化查询
- `/get_proxy_reenc_info` - 获取代理重加密信息
- `/ars_create_sec_keys` - ARS 创建密钥
- `/accounts_valid` - 账户验证
- `/commit_gid_valid` - GID 验证
- `/prefund_valid` - 预付款验证
- `/get_block_with_gid` - 通过 GID 获取区块
- `/get_blocks` - 获取区块
- `/get_latest_pool_info` - 获取最新池信息
- `/get_block_with_hash` - 通过哈希获取区块
- `/transaction_receipt` - 交易回执
- `/get_seckey_and_encrypt_data` - 获取密钥和加密数据
- `/proxy_decrypt` - 代理解密

## 性能优势

uWebSockets 相比 httplib 的优势：

1. **更高性能**: uWebSockets 是目前最快的 HTTP/WebSocket 服务器之一
2. **更低延迟**: 基于 epoll/kqueue 的事件驱动架构
3. **更好的并发**: 原生支持高并发连接
4. **更小内存占用**: 优化的内存管理

## 安全性

- 使用 TLS 1.2+ 加密所有通信
- 自签名证书适用于内部测试和开发
- 生产环境建议使用 CA 签发的证书

## 编译依赖

确保系统已安装以下依赖：

```bash
# macOS
brew install openssl uwebsockets

# Linux (Ubuntu/Debian)
apt-get install libssl-dev libz-dev

# 手动安装 uWebSockets
git clone https://github.com/uNetworking/uWebSockets.git
cd uWebSockets
# 将头文件复制到 third_party/include/uWebSockets/
```

## 使用说明

### 客户端连接

由于使用自签名证书，客户端需要跳过证书验证或添加证书到信任列表：

```python
# Python 示例
import requests

# 跳过证书验证（仅用于测试）
response = requests.post('https://localhost:8080/transaction', 
                        data=payload, 
                        verify=False)

# 或指定证书
response = requests.post('https://localhost:8080/transaction', 
                        data=payload, 
                        verify='server-cert.pem')
```

```bash
# curl 示例
curl -k -X POST https://localhost:8080/transaction -d "param=value"

# 或指定证书
curl --cacert server-cert.pem -X POST https://localhost:8080/transaction -d "param=value"
```

## 注意事项

1. 证书文件 (`server-cert.pem` 和 `server-key.pem`) 必须放在可执行文件的工作目录
2. 自签名证书会导致浏览器显示安全警告，这是正常的
3. 生产环境应使用正式的 CA 签发证书
4. 确保防火墙允许 HTTPS 端口（默认 443 或自定义端口）

## 回滚方案

如需回滚到 httplib：

1. 恢复备份文件（如果有）
2. 或使用 git 回退到之前的提交

## 测试

编译并运行服务器后，可以使用以下命令测试：

```bash
# 测试 HTTPS 连接
curl -k https://localhost:8080/query_init

# 应返回 "ok"
```

## 后续优化建议

1. 添加证书自动更新机制
2. 支持 HTTP/2
3. 添加请求限流和防护
4. 实现连接池管理
5. 添加详细的性能监控
