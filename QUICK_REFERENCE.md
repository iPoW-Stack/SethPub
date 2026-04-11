# 快速参考卡片

## 🚀 一键启动

```bash
./quick_start.sh
cd build && ./seth
```

## 📦 手动安装

```bash
# 1. 安装 uWebSockets
./install_uwebsockets.sh

# 2. 生成证书
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem \
    -out server-cert.pem -days 365 -nodes \
    -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"

# 3. 编译
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make seth -j$(nproc)

# 4. 运行
./seth
```

## 🧪 测试命令

```bash
# 基本测试
curl -k https://localhost:8080/query_init

# Python 测试
python3 test_https_client.py

# 压力测试
wrk -t12 -c400 -d30s https://localhost:8080/query_init
```

## 📋 主要变更

| 项目 | 旧版本 | 新版本 |
|------|--------|--------|
| HTTP 库 | cpp-httplib | uWebSockets |
| 协议 | HTTP | HTTPS |
| 性能 | ~10K req/s | ~100K+ req/s |
| 延迟 | ~10ms | ~1ms |

## 🔧 常见问题

### OpenSSL 找不到
```bash
# macOS
export OPENSSL_ROOT_DIR=/usr/local/opt/openssl@3
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@3 ..
```

### 端口被占用
```bash
lsof -i :8080
kill -9 <PID>
```

### 证书权限问题
```bash
chmod 600 server-key.pem
chmod 644 server-cert.pem
```

## 📖 文档索引

- **迁移指南**: `HTTPS_MIGRATION.md`
- **编译指南**: `BUILD_GUIDE.md`
- **变更日志**: `CHANGES.md`
- **完整总结**: `FINAL_SUMMARY.md`

## 🔗 API 端点

所有端点从 `http://` 改为 `https://`

```
https://localhost:8080/transaction
https://localhost:8080/query_account
https://localhost:8080/query_contract
... (共 18 个端点)
```

## 💡 客户端示例

### Python
```python
import requests
requests.post('https://localhost:8080/transaction', 
              data=payload, verify=False)
```

### curl
```bash
curl -k -X POST https://localhost:8080/transaction \
     -d "param=value"
```

### JavaScript
```javascript
fetch('https://localhost:8080/transaction', {
    method: 'POST',
    body: formData
})
```

## ⚡ 性能优化

```bash
# 系统调优
sudo sysctl -w net.core.somaxconn=4096
ulimit -n 65535

# CPU 亲和性
taskset -c 0-7 ./seth
```

## 🔒 生产环境

```bash
# 使用 Let's Encrypt
sudo certbot certonly --standalone -d your-domain.com

# 更新证书路径（在代码中）
cert_file_ = "/etc/letsencrypt/live/your-domain.com/fullchain.pem";
key_file_ = "/etc/letsencrypt/live/your-domain.com/privkey.pem";
```

## 📞 获取帮助

1. 查看文档目录
2. 检查日志文件
3. 提交 GitHub Issue

---

**版本**: 2.0.0 | **日期**: 2026-04-12
