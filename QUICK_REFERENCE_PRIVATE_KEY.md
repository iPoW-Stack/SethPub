# 私钥更新 - 快速参考

## 🚀 快速使用

```bash
# 方法 1: 使用测试脚本（推荐）
python3 test_update_private_key.py <hex_private_key>

# 方法 2: 使用 curl
curl -k -X POST https://localhost:8080/update_private_key \
  -d "private_key=<hex_private_key>"
```

## 📋 API 信息

| 项目 | 值 |
|------|-----|
| 端点 | `/update_private_key` |
| 方法 | POST |
| 协议 | HTTPS |
| 参数 | `private_key` (hex string) |

## ✅ 成功响应

```json
{
  "status": 0,
  "msg": "success"
}
```

## ❌ 失败响应

```json
{
  "status": 1,
  "msg": "error message"
}
```

## 🔑 私钥格式

### 原始私钥（32 字节）
```
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```
长度: 64 个十六进制字符

### 加密私钥
```
<encrypted_hex_string>
```
长度: > 64 个十六进制字符

## 📝 使用示例

### Python
```python
import requests

response = requests.post(
    "https://localhost:8080/update_private_key",
    data={"private_key": "0123...cdef"},
    verify=False
)
print(response.json())
```

### Bash
```bash
NEW_KEY="0123456789abcdef..."
curl -k -X POST https://localhost:8080/update_private_key \
  -d "private_key=$NEW_KEY"
```

## 🔍 验证更新

```bash
# 1. 更新前查询地址
curl -k https://localhost:8080/query_init

# 2. 更新私钥
python3 test_update_private_key.py <new_key>

# 3. 更新后查询地址（应该不同）
curl -k https://localhost:8080/query_init
```

## ⚠️ 注意事项

1. ✅ 使用 HTTPS（不是 HTTP）
2. ✅ 备份旧私钥
3. ✅ 验证新私钥格式
4. ✅ 检查更新日志
5. ⚠️ 地址会改变

## 🐛 常见错误

| 错误 | 原因 | 解决 |
|------|------|------|
| "parameter is required" | 缺少参数 | 添加 private_key 参数 |
| "invalid format" | 格式错误 | 使用十六进制字符串 |
| "failed to set" | 长度错误 | 检查私钥长度 |

## 📚 完整文档

详细信息请查看:
- [UPDATE_PRIVATE_KEY_API.md](UPDATE_PRIVATE_KEY_API.md)
- [PRIVATE_KEY_UPDATE_SUMMARY.md](PRIVATE_KEY_UPDATE_SUMMARY.md)

---

**版本**: 2.1.0 | **日期**: 2026-04-12
