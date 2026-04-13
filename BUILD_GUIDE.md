# 编译和部署指南

## 前置条件

### 系统要求
- macOS 10.15+ 或 Linux (Ubuntu 18.04+, CentOS 7+)
- CMake 3.22+
- C++20 编译器 (GCC 10+, Clang 12+, 或 Apple Clang 13+)
- OpenSSL 1.1.1+

### 依赖安装

#### macOS
```bash
# 使用 Homebrew 安装依赖
brew install cmake openssl@3 zlib

# 设置 OpenSSL 环境变量
export OPENSSL_ROOT_DIR=/usr/local/opt/openssl@3
export PKG_CONFIG_PATH=/usr/local/opt/openssl@3/lib/pkgconfig
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    zlib1g-dev \
    git
```

#### CentOS/RHEL
```bash
sudo yum install -y \
    gcc-c++ \
    cmake3 \
    openssl-devel \
    zlib-devel \
    git
```

## 安装步骤

### 1. 安装 uWebSockets

运行提供的安装脚本：

```bash
./install_uwebsockets.sh
```

或手动安装：

```bash
# 创建临时目录
mkdir -p /tmp/uws_build && cd /tmp/uws_build

# 克隆并编译 uSockets
git clone https://github.com/uNetworking/uSockets.git
cd uSockets
WITH_OPENSSL=1 make
cp uSockets.a ../third_party/lib/libuSockets.a
mkdir -p ../third_party/include/uSockets
cp src/*.h ../third_party/include/uSockets/

# 克隆 uWebSockets (header-only)
cd /tmp/uws_build
git clone https://github.com/uNetworking/uWebSockets.git
mkdir -p ../third_party/include/uWebSockets
cp -r uWebSockets/src/* ../third_party/include/uWebSockets/

# 清理
cd .. && rm -rf /tmp/uws_build
```

### 2. 生成 SSL 证书

如果还没有生成证书，运行：

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout server-key.pem \
    -out server-cert.pem \
    -days 365 -nodes \
    -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"
```

这将生成：
- `server-cert.pem` - SSL 证书
- `server-key.pem` - 私钥

### 3. 编译项目

```bash
# 创建构建目录
mkdir -p build && cd build

# 配置 CMake (Release 模式，性能优化)
cmake -DCMAKE_BUILD_TYPE=Release ..

# 编译 (使用多核加速)
make -j$(nproc)

# 或者只编译 seth 主程序
make seth -j$(nproc)
```

#### 编译选项

```bash
# Debug 模式（包含调试符号）
cmake -DCMAKE_BUILD_TYPE=Debug ..

# 指定 OpenSSL 路径（如果自动检测失败）
cmake -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@3 \
      ..

# 禁用 LTO（如果遇到链接问题）
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
      ..
```

### 4. 验证编译

```bash
# 检查可执行文件
ls -lh seth

# 检查依赖库
ldd seth  # Linux
otool -L seth  # macOS

# 应该看到 libssl, libcrypto, libz 等库
```

## 运行服务器

### 1. 准备配置

确保证书文件在正确位置：

```bash
# 将证书复制到运行目录
cp server-cert.pem server-key.pem /path/to/run/directory/
```

### 2. 启动服务器

```bash
# 基本启动
./seth

# 指定配置文件
./seth --config config.conf

# 后台运行
nohup ./seth > seth.log 2>&1 &

# 使用 systemd (推荐生产环境)
sudo systemctl start seth
```

### 3. 验证服务器

```bash
# 测试 HTTPS 连接
curl -k https://localhost:8080/query_init

# 应返回 "ok"

# 使用 Python 测试脚本
python3 test_https_client.py

# 查看服务器日志
tail -f seth.log
```

## 常见问题

### 1. OpenSSL 找不到

**错误**: `Could not find OpenSSL`

**解决方案**:
```bash
# macOS
export OPENSSL_ROOT_DIR=/usr/local/opt/openssl@3
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@3 ..

# Linux - 安装开发包
sudo apt-get install libssl-dev  # Ubuntu
sudo yum install openssl-devel   # CentOS
```

### 2. uWebSockets 头文件找不到

**错误**: `fatal error: App.h: No such file or directory`

**解决方案**:
```bash
# 确认头文件位置
ls third_party/include/uWebSockets/App.h

# 如果不存在，重新运行安装脚本
./install_uwebsockets.sh
```

### 3. uSockets 库链接失败

**错误**: `undefined reference to uWS::...`

**解决方案**:
```bash
# 确认库文件存在
ls third_party/lib/libuSockets.a

# 检查 CMakeLists.txt 中的链接配置
# 应包含: uSockets ssl crypto z
```

### 4. 证书权限问题

**错误**: `Permission denied` 读取证书文件

**解决方案**:
```bash
# 修改证书文件权限
chmod 600 server-key.pem
chmod 644 server-cert.pem

# 确保运行用户有读取权限
chown $USER:$USER server-*.pem
```

### 5. 端口被占用

**错误**: `Failed to listen on 0.0.0.0:8080`

**解决方案**:
```bash
# 查找占用端口的进程
lsof -i :8080  # macOS/Linux
netstat -ano | findstr :8080  # Windows

# 杀死进程或更改配置文件中的端口
```

### 6. 编译时内存不足

**错误**: `c++: fatal error: Killed signal terminated program cc1plus`

**解决方案**:
```bash
# 减少并行编译任务数
make -j2  # 只使用 2 个核心

# 或增加交换空间
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## 性能优化

### 1. 编译优化

```bash
# 使用 -march=native 优化（已在 CMakeLists.txt 中配置）
cmake -DCMAKE_BUILD_TYPE=Release ..

# 启用 LTO（已默认启用）
cmake -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON ..
```

### 2. 运行时优化

```bash
# 设置 CPU 亲和性
taskset -c 0-7 ./seth

# 提高文件描述符限制
ulimit -n 65535

# 使用 tcmalloc（已在链接配置中）
LD_PRELOAD=/usr/lib/libtcmalloc.so ./seth
```

### 3. 系统调优

```bash
# Linux 网络优化
sudo sysctl -w net.core.somaxconn=4096
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sudo sysctl -w net.core.netdev_max_backlog=4096

# 持久化配置
echo "net.core.somaxconn=4096" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 生产环境部署

### 1. 使用正式证书

```bash
# 从 Let's Encrypt 获取免费证书
sudo certbot certonly --standalone -d your-domain.com

# 更新配置使用正式证书
# 修改 http_handler.cc 中的证书路径
cert_file_ = "/etc/letsencrypt/live/your-domain.com/fullchain.pem";
key_file_ = "/etc/letsencrypt/live/your-domain.com/privkey.pem";
```

### 2. Systemd 服务配置

创建 `/etc/systemd/system/seth.service`:

```ini
[Unit]
Description=Seth HTTPS Server
After=network.target

[Service]
Type=simple
User=seth
Group=seth
WorkingDirectory=/opt/seth
ExecStart=/opt/seth/seth
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable seth
sudo systemctl start seth
sudo systemctl status seth
```

### 3. 反向代理（可选）

使用 Nginx 作为反向代理：

```nginx
upstream seth_backend {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass https://seth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 监控和日志

### 1. 日志配置

```bash
# 使用 logrotate 管理日志
sudo tee /etc/logrotate.d/seth <<EOF
/var/log/seth/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 seth seth
    sharedscripts
    postrotate
        systemctl reload seth > /dev/null 2>&1 || true
    endscript
}
EOF
```

### 2. 性能监控

```bash
# 使用 htop 监控资源使用
htop -p $(pgrep seth)

# 使用 netstat 监控连接
watch -n 1 'netstat -an | grep :8080 | wc -l'

# 使用 perf 进行性能分析
sudo perf record -g -p $(pgrep seth)
sudo perf report
```

## 更新和维护

### 1. 更新代码

```bash
git pull origin main
cd build
make clean
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo systemctl restart seth
```

### 2. 备份

```bash
# 备份可执行文件和配置
tar -czf seth-backup-$(date +%Y%m%d).tar.gz \
    seth \
    server-*.pem \
    config.conf

# 备份数据库（如果有）
tar -czf seth-data-$(date +%Y%m%d).tar.gz data/
```

## 支持

如有问题，请查看：
- 项目文档: `HTTPS_MIGRATION.md`
- 日志文件: `seth.log`
- GitHub Issues: [项目地址]

## 许可证

[根据项目实际情况填写]
