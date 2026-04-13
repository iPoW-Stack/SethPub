# 私钥等待功能快速开始

## 功能简介

当配置文件中没有私钥时，程序会启动 HTTP 服务器并等待通过 API 接收私钥，而不是直接退出。

## 快速使用

### 1. 配置文件设置

编辑 `conf/seth.conf`，清空或删除 `prikey` 配置：

```ini
[seth]
prikey=
http_port=8080
```

### 2. 启动程序

```bash
./seth -c conf/seth.conf
```

程序会输出：

```
[WARN] Private key is empty or not found in config, waiting for UpdatePrivateKey...
[INFO] HTTP server started, waiting for private key update via /update_private_key endpoint...
[INFO] Please send POST request to http://0.0.0.0:8080/update_private_key with private_key parameter
[INFO] Waiting for private key update...
```

### 3. 发送私钥

使用 curl：

```bash
curl -X POST http://localhost:8080/update_private_key \
  -d "private_key=YOUR_HEX_ENCODED_PRIVATE_KEY"
```

或使用 Python 测试脚本：

```bash
python3 test_private_key_wait.py
```

### 4. 程序继续运行

收到私钥后，程序会输出：

```
[INFO] Private key received, resuming initialization...
[INFO] Initial private key setup: new address: 0x...
[INFO] Configuration updated with new private key
[INFO] Private key updated successfully!
```

然后继续完成初始化并正常运行。

## 私钥格式

私钥必须是十六进制编码的字符串：

- **原始私钥**：64个十六进制字符（32字节）
  ```
  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  ```

- **加密私钥**：更长的十六进制字符串（加密后的格式）

## 注意事项

1. **HTTP 端口必须配置**：确保 `seth.conf` 中设置了 `http_port`
2. **私钥会被保存**：接收到的私钥会自动保存到配置文件
3. **只在启动时等待**：程序运行后仍可通过 API 更新私钥，但不会阻塞

## 故障排查

### 问题：程序立即退出

**原因**：HTTP 端口未配置

**解决**：在 `seth.conf` 中添加：
```ini
http_port=8080
```

### 问题：发送私钥后无响应

**原因**：私钥格式错误

**解决**：确保私钥是有效的十六进制字符串

### 问题：无法连接到 HTTP 服务器

**原因**：端口被占用或防火墙阻止

**解决**：
- 检查端口是否被占用：`netstat -an | grep 8080`
- 更换端口或关闭占用端口的程序

## 相关文档

- `PRIVATE_KEY_WAIT_FEATURE.md` - 详细功能说明
- `CRASH_FIX_PRIVATE_KEY_WAIT.md` - 崩溃修复说明
- `IMPLEMENTATION_SUMMARY.md` - 实现细节
- `test_private_key_wait.py` - Python 测试脚本
