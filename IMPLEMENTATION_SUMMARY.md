# 私钥等待功能实现总结

## 需求
如果本地 `seth.conf` 的 `privatekey` 为空或者不存在，则等待 `UpdatePrivateKey`，然后再继续运行程序。

## 实现方案

### 1. 核心思路
- 在 `InitSecurity()` 检测到私钥为空时，返回特殊状态码 `kInitWaitingForPrivateKey`
- 在 `Init()` 方法中检测到该状态码后：
  1. 初始化最小化的组件（DB、HTTP服务器）
  2. 启动HTTP服务器并注册私钥更新回调
  3. 阻塞等待私钥更新
  4. 收到私钥后继续完成剩余初始化

### 2. 修改的文件

#### src/init/init_utils.h
```cpp
enum InitErrorCode {
    kInitSuccess = 0,
    kInitError = 1,
    kInitWaitingForPrivateKey = 2,  // 新增状态码
};
```

#### src/init/network_init.h
新增方法声明：
```cpp
int InitHttpServerForPrivateKeyWait();
void WaitForPrivateKeyUpdate();
```

新增成员变量：
```cpp
// 私钥等待机制
std::mutex private_key_wait_mutex_;
std::condition_variable private_key_wait_cv_;
std::atomic<bool> private_key_received_{false};
```

#### src/init/network_init.cc

**修改 InitSecurity():**
```cpp
int NetworkInit::InitSecurity() {
    std::string prikey;
    if (!conf_.Get("seth", "prikey", prikey) || prikey.empty()) {
        INIT_WARN("Private key is empty or not found in config, waiting for UpdatePrivateKey...");
        return kInitWaitingForPrivateKey;  // 返回特殊状态码
    }
    // ... 原有逻辑
}
```

**修改 Init():**
```cpp
int NetworkInit::Init(int argc, char** argv) {
    // ... 前置初始化
    
    int security_init_result = InitSecurity();
    if (security_init_result == kInitWaitingForPrivateKey) {
        // 初始化最小化组件
        // 启动HTTP服务器
        InitHttpServerForPrivateKeyWait();
        
        // 等待私钥更新
        WaitForPrivateKeyUpdate();
        
        // 继续初始化
    }
    // ... 剩余初始化逻辑
}
```

**新增 InitHttpServerForPrivateKeyWait():**
```cpp
int NetworkInit::InitHttpServerForPrivateKeyWait() {
    // 获取HTTP配置
    std::string http_ip = "0.0.0.0";
    uint16_t http_port = 0;
    conf_.Get("seth", "http_ip", http_ip);
    if (!conf_.Get("seth", "http_port", http_port) || http_port == 0) {
        INIT_ERROR("HTTP port not configured!");
        return kInitError;
    }
    
    // 创建最小化的account_mgr
    account_mgr_ = std::make_shared<block::AccountManager>();
    
    // 设置私钥更新回调
    http_handler_.SetPrivateKeyUpdateCallback(
        [this](const std::string& new_private_key) -> int {
            return this->UpdatePrivateKey(new_private_key);
        });
    
    // 初始化HTTP处理器
    http_handler_.Init(
        account_mgr_, 
        nullptr,  // net_handler暂时不需要
        security_, 
        prefix_db_, 
        nullptr,  // contract_mgr暂时不需要
        http_ip, 
        http_port);
    
    return kInitSuccess;
}
```

**新增 WaitForPrivateKeyUpdate():**
```cpp
void NetworkInit::WaitForPrivateKeyUpdate() {
    INIT_INFO("Waiting for private key update...");
    std::unique_lock<std::mutex> lock(private_key_wait_mutex_);
    private_key_wait_cv_.wait(lock, [this] { 
        return private_key_received_.load(); 
    });
    INIT_INFO("Private key received, resuming initialization...");
}
```

**修改 UpdatePrivateKey():**
```cpp
int NetworkInit::UpdatePrivateKey(const std::string& new_private_key) {
    // ... 原有的私钥验证和更新逻辑
    
    // 新增：通知等待线程
    {
        std::lock_guard<std::mutex> lock(private_key_wait_mutex_);
        private_key_received_ = true;
    }
    private_key_wait_cv_.notify_one();
    
    return kInitSuccess;
}
```

## 工作流程

```
程序启动
    ↓
InitConfigWithArgs() - 加载配置文件
    ↓
GlobalInfo::Init() - 初始化全局信息
    ↓
InitSecurity() - 尝试加载私钥
    ↓
私钥是否存在？
    ├─ 是 → 继续正常初始化流程
    │       ↓
    │   初始化所有组件
    │       ↓
    │   启动服务
    │
    └─ 否 → 进入私钥等待模式
            ↓
        初始化DB和prefix_db
            ↓
        创建临时security对象
            ↓
        InitHttpServerForPrivateKeyWait()
            ├─ 创建account_mgr
            ├─ 设置私钥更新回调
            └─ 启动HTTP服务器
            ↓
        WaitForPrivateKeyUpdate()
            └─ 阻塞等待条件变量
            ↓
        用户通过POST /update_private_key发送私钥
            ↓
        UpdatePrivateKey()
            ├─ 验证私钥
            ├─ 更新security_对象
            ├─ 保存到配置文件
            └─ 通知条件变量
            ↓
        WaitForPrivateKeyUpdate()返回
            ↓
        继续完成剩余的初始化流程
            ↓
        程序正常运行
```

## 关键技术点

### 1. 条件变量同步
使用 `std::condition_variable` 实现线程间同步：
- 主线程在 `WaitForPrivateKeyUpdate()` 中等待
- HTTP处理线程在 `UpdatePrivateKey()` 中通知

### 2. 最小化初始化
在等待私钥时只初始化必要的组件：
- DB（数据库）
- prefix_db（前缀数据库）
- account_mgr（账户管理器，最小化版本）
- HTTP服务器

### 3. 避免重复初始化
在 `Init()` 方法中检查组件是否已初始化：
```cpp
if (!db_) {
    db_ = std::make_shared<db::Db>();
    // ...
}
```

### 4. 配置持久化
接收到私钥后保存到配置文件：
```cpp
std::string prikey_hex = common::Encode::HexEncode(new_private_key);
conf_.Set("seth", "prikey", prikey_hex);
```

## 使用示例

### 1. 配置文件设置
编辑 `conf/seth.conf`：
```ini
[seth]
prikey=
http_port=8080
```

### 2. 启动程序
```bash
./seth -c conf/seth.conf
```

程序输出：
```
[WARN] Private key is empty or not found in config, waiting for UpdatePrivateKey...
[INFO] HTTP server started, waiting for private key update via /update_private_key endpoint...
[INFO] Please send POST request to http://0.0.0.0:8080/update_private_key with private_key parameter
[INFO] Waiting for private key update...
```

### 3. 发送私钥
```bash
curl -X POST http://localhost:8080/update_private_key \
  -d "private_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

或使用Python脚本：
```bash
python3 test_private_key_wait.py
```

### 4. 程序继续运行
```
[INFO] Private key received, resuming initialization...
[INFO] Private key updated successfully! New address: 0x...
[INFO] Continuing initialization...
```

## 测试

### 测试脚本
提供了两个测试脚本：
1. `test_private_key_wait.sh` - Bash脚本
2. `test_private_key_wait.py` - Python脚本（推荐）

### 测试步骤
1. 备份配置文件
2. 清空私钥配置
3. 启动程序
4. 运行测试脚本发送私钥
5. 验证程序继续运行

## 安全考虑

### 1. 传输安全
- 当前使用HTTP传输私钥
- 生产环境建议：
  - 使用HTTPS加密传输
  - 添加身份验证（API密钥、JWT等）
  - IP白名单限制

### 2. 存储安全
- 私钥保存到配置文件
- 建议设置文件权限：`chmod 600 conf/seth.conf`

### 3. 日志安全
- 私钥不会完整记录到日志
- 只记录地址信息用于调试

## 优点

1. **用户友好**: 程序不会因缺少私钥而退出
2. **灵活性**: 支持动态配置私钥
3. **最小化影响**: 只在需要时才等待，不影响正常流程
4. **线程安全**: 使用条件变量确保线程同步
5. **可测试**: 提供测试脚本便于验证

## 潜在改进

1. **超时机制**: 添加等待超时，避免无限等待
2. **重试机制**: 私钥验证失败后允许重试
3. **通知机制**: 通过WebSocket或其他方式通知客户端状态
4. **配置选项**: 添加配置项控制是否启用等待模式

## 相关文档

- `PRIVATE_KEY_WAIT_FEATURE.md` - 功能详细说明
- `PRIVATE_KEY_UPDATE_SUMMARY.md` - 私钥更新功能总结
- `UPDATE_PRIVATE_KEY_API.md` - API文档
- `test_private_key_wait.py` - Python测试脚本
- `test_private_key_wait.sh` - Bash测试脚本
