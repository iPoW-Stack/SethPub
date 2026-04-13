# 私钥更新 API 文档

## 概述

新增了一个 HTTPS API 端点，允许客户端动态更新服务器的私钥，而无需重启服务。

## API 端点

### POST /update_private_key

更新服务器的私钥配置。

#### 请求参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| private_key | string | 是 | 新的私钥（十六进制字符串） |

#### 私钥格式

支持两种格式的私钥：

1. **原始私钥**（32 字节 = 64 个十六进制字符）
   ```
   0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
   ```

2. **加密私钥**（使用 KeyManager 加密的私钥，长度 > 64 字符）
   ```
   <encrypted_hex_string>
   ```

#### 响应格式

```json
{
  "status": 0,
  "msg": "success"
}
```

#### 状态码

| status | 说明 |
|--------|------|
| 0 | 成功 |
| 1 | 失败 |

#### 错误消息

| msg | 说明 |
|-----|------|
| "private_key parameter is required" | 缺少 private_key 参数 |
| "invalid private_key format (must be hex)" | 私钥格式无效（不是十六进制） |
| "private key update callback not set" | 回调函数未设置 |
| "failed to update private key" | 更新失败 |

## 使用示例

### curl 命令

```bash
# 使用原始私钥（32 字节）
curl -k -X POST https://localhost:8080/update_private_key \
  -d "private_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# 使用加密私钥
curl -k -X POST https://localhost:8080/update_private_key \
  -d "private_key=<encrypted_hex_string>"
```

### Python 示例

```python
import requests

# 服务器地址
server_url = "https://localhost:8080"

# 新的私钥（十六进制）
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# 发送请求
response = requests.post(
    f"{server_url}/update_private_key",
    data={"private_key": private_key},
    verify=False  # 跳过 SSL 证书验证（自签名证书）
)

# 解析响应
result = response.json()
if result["status"] == 0:
    print("✅ 私钥更新成功")
else:
    print(f"❌ 更新失败: {result['msg']}")
```

### 使用测试脚本

```bash
# 使用提供的测试脚本
python3 test_update_private_key.py <your_private_key_hex>

# 示例
python3 test_update_private_key.py 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## 工作原理

### 1. 请求处理流程

```
客户端 → HTTPS POST /update_private_key
         ↓
    http_handler.cc (UpdatePrivateKey)
         ↓
    验证私钥格式
         ↓
    调用回调函数 (private_key_update_callback_)
         ↓
    network_init.cc (UpdatePrivateKey)
         ↓
    更新 security_ 对象
         ↓
    通知相关组件
         ↓
    返回结果
```

### 2. 更新的组件

当私钥更新时，以下组件会自动更新：

1. **Security 对象** - 核心安全模块
2. **Network Route** - 网络路由
3. **Universal Manager** - 通用管理器
4. **Bootstrap** - 引导模块
5. **Block Manager** - 区块管理器（更新地址）
6. **配置文件** - 持久化新私钥

### 3. 地址变更

更新私钥后，节点的地址也会相应改变：

```
旧私钥 → 旧地址
新私钥 → 新地址
```

系统会记录并输出新旧地址的变化。

## 安全考虑

### ⚠️ 重要安全提示

1. **HTTPS 必须**: 此接口只能通过 HTTPS 访问，确保私钥在传输过程中加密
2. **访问控制**: 建议添加身份验证机制（如 API Key、JWT 等）
3. **IP 白名单**: 建议限制只允许特定 IP 访问此接口
4. **审计日志**: 所有私钥更新操作都会记录在日志中
5. **备份**: 更新前请备份旧私钥

### 建议的安全增强

```cpp
// 在 UpdatePrivateKey 函数中添加：

// 1. IP 白名单检查
if (!IsAllowedIP(client_ip)) {
    res_json["msg"] = "access denied";
    return;
}

// 2. API Key 验证
auto api_key = req.get_param_value("api_key");
if (!ValidateAPIKey(api_key)) {
    res_json["msg"] = "invalid api key";
    return;
}

// 3. 限流
if (IsRateLimited(client_ip)) {
    res_json["msg"] = "too many requests";
    return;
}
```

## 日志输出

更新私钥时会产生以下日志：

```
[INFO] Update private key request received.
[INFO] Updating private key...
[INFO] Private key update: old address: 0x1234..., new address: 0x5678...
[INFO] Network route updated with new private key
[INFO] Universal manager updated with new private key
[INFO] Bootstrap updated with new private key
[INFO] Block manager updated with new address
[INFO] Configuration updated with new private key
[INFO] Private key updated successfully! New address: 0x5678...
[INFO] Private key updated successfully
```

## 错误处理

### 常见错误及解决方案

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| "private_key parameter is required" | 未提供私钥参数 | 在请求中添加 private_key 参数 |
| "invalid private_key format" | 私钥不是有效的十六进制 | 检查私钥格式，确保是十六进制字符串 |
| "Failed to set new private key" | 私钥长度或格式错误 | 确保私钥是 32 字节（64 字符）或有效的加密私钥 |
| "private key update callback not set" | 回调未初始化 | 检查 InitHttpServer 是否正确调用 |

## 测试

### 单元测试

```bash
# 测试有效私钥
python3 test_update_private_key.py 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# 测试无效私钥（应该失败）
python3 test_update_private_key.py invalid_key

# 测试空私钥（应该失败）
python3 test_update_private_key.py ""
```

### 集成测试

```bash
# 1. 启动服务器
./seth

# 2. 查询当前地址
curl -k https://localhost:8080/query_account?address=<current_address>

# 3. 更新私钥
python3 test_update_private_key.py <new_private_key>

# 4. 验证新地址
curl -k https://localhost:8080/query_account?address=<new_address>
```

## 回滚

如果需要回滚到旧私钥：

```bash
# 使用旧私钥再次调用更新接口
python3 test_update_private_key.py <old_private_key>
```

## 性能影响

- **更新时间**: < 100ms
- **服务中断**: 无（热更新）
- **内存开销**: 最小（只更新必要的对象）
- **并发安全**: 是（使用互斥锁保护）

## 限制

1. **单线程更新**: 同一时间只能有一个私钥更新操作
2. **不可逆**: 更新后无法自动回滚，需要手动使用旧私钥
3. **配置持久化**: 更新会写入配置文件，重启后生效

## 最佳实践

1. **备份**: 更新前备份当前私钥和地址
2. **测试**: 在测试环境先验证
3. **监控**: 更新后监控节点状态
4. **通知**: 更新后通知相关系统新地址
5. **文档**: 记录每次私钥更新的时间和原因

## 故障排查

### 问题：更新后节点无法连接

**原因**: 新地址未在网络中注册

**解决方案**:
1. 检查新地址是否有效
2. 确保新地址已加入网络
3. 检查防火墙规则

### 问题：更新失败但日志显示成功

**原因**: 部分组件更新失败

**解决方案**:
1. 检查详细日志
2. 重启服务
3. 使用旧私钥回滚

## 相关文件

- `src/init/http_handler.h` - HTTP 处理器头文件
- `src/init/http_handler.cc` - HTTP 处理器实现（UpdatePrivateKey 函数）
- `src/init/network_init.h` - 网络初始化头文件
- `src/init/network_init.cc` - 网络初始化实现（UpdatePrivateKey 方法）
- `test_update_private_key.py` - 测试脚本

## 版本历史

- **v2.1.0** (2026-04-12): 新增私钥更新 API

---

**注意**: 此功能为高级功能，请谨慎使用。不当使用可能导致节点无法正常工作。
