# 私钥等待功能崩溃修复

## 问题描述

在实现私钥等待功能后，程序在等待私钥期间崩溃，堆栈信息显示：

```
Thread 3 "seth" received signal SIGSEGV, Segmentation fault.
#0  0x0000555556d5cb10 in uv_async_send ()
#1  0x0000555556d5c84c in uv_async_send ()
#2  0x0000555555b810df in seth::transport::TcpTransport::AddLocalMessage
#3  0x0000555555b0a6ff in seth::bls::BlsDkg::BroadcastFinish
#4  0x0000555555b08bec in seth::bls::BlsDkg::FinishBroadcast
#5  0x0000555555affec2 in seth::bls::BlsDkg::TimerMessage
#6  0x0000555555ad9370 in seth::bls::BlsManager::TimerMessage
```

## 根本原因

在私钥等待模式下，程序的初始化流程被中断：

1. 创建了临时的 `security_` 对象用于 HTTP 服务器初始化
2. 但是 `TcpTransport`、`bls_mgr_` 等组件还没有初始化
3. 当 `bls_mgr_->TimerMessage()` 被调用时，尝试通过 `TcpTransport::AddLocalMessage()` 发送消息
4. 由于 `TcpTransport` 还没有初始化，`uv_async_send()` 访问了无效的内存地址，导致段错误

## 解决方案

### 1. 不在等待期间创建临时 security 对象

**修改前：**
```cpp
// Create a temporary security object for HTTP server initialization
security_ = std::make_shared<security::Ecdsa>();

// Initialize HTTP server with private key update callback
if (InitHttpServerForPrivateKeyWait() != kInitSuccess) {
    // ...
}
```

**修改后：**
```cpp
// Initialize HTTP server with private key update callback
// (不创建 security_ 对象)
if (InitHttpServerForPrivateKeyWait() != kInitSuccess) {
    // ...
}

// Wait for private key to be updated
WaitForPrivateKeyUpdate();

// Now re-initialize security with the received private key
security_init_result = InitSecurity();
if (security_init_result != kInitSuccess) {
    INIT_ERROR("InitSecurity failed after receiving private key!");
    return kInitError;
}
```

### 2. 在 InitHttpServerForPrivateKeyWait 中使用局部临时对象

**修改：**
```cpp
int NetworkInit::InitHttpServerForPrivateKeyWait() {
    // ...
    
    // Create a temporary empty security object just for HTTP handler initialization
    // This will be replaced with the real one after private key is received
    auto temp_security = std::make_shared<security::Ecdsa>();
    
    // Initialize HTTP handler with minimal components
    http_handler_.Init(
        account_mgr_, 
        nullptr,  // net_handler not initialized yet
        temp_security,  // temporary security object (局部变量)
        prefix_db_, 
        nullptr,  // contract_mgr not initialized yet
        http_ip, 
        http_port);
    
    // ...
}
```

### 3. 修复 UpdatePrivateKey 方法

**问题：** 在初始设置时，`security_` 可能是 nullptr，调用 `security_->GetAddress()` 会崩溃。

**修改：**
```cpp
int NetworkInit::UpdatePrivateKey(const std::string& new_private_key) {
    // ... 验证私钥
    
    // Check if this is initial private key setup or update
    bool is_initial_setup = (security_ == nullptr || private_key_received_ == false);
    
    if (!is_initial_setup) {
        // 运行时更新：记录旧地址
        std::string old_address = security_->GetAddress();
        SETH_INFO("Private key update: old address: %s, new address: %s", ...);
    } else {
        // 初始设置：只记录新地址
        SETH_INFO("Initial private key setup: new address: %s", ...);
    }
    
    // 保存到配置文件
    conf_.Set("seth", "prikey", prikey_hex);
    
    if (is_initial_setup) {
        // 初始设置：只通知等待线程，不更新 security_
        // security_ 将在 WaitForPrivateKeyUpdate() 返回后由 InitSecurity() 初始化
        {
            std::lock_guard<std::mutex> lock(private_key_wait_mutex_);
            private_key_received_ = true;
        }
        private_key_wait_cv_.notify_one();
    } else {
        // 运行时更新：直接更新 security_ 对象
        security_ = new_security;
    }
    
    return kInitSuccess;
}
```

## 修复后的工作流程

```
程序启动
    ↓
InitSecurity() - 检测私钥为空
    ↓
返回 kInitWaitingForPrivateKey
    ↓
初始化 DB 和 prefix_db
    ↓
InitHttpServerForPrivateKeyWait()
    ├─ 创建 account_mgr
    ├─ 创建局部临时 security 对象
    ├─ 设置私钥更新回调
    └─ 启动 HTTP 服务器
    ↓
WaitForPrivateKeyUpdate()
    └─ 阻塞等待条件变量
    ↓
用户发送 POST /update_private_key
    ↓
UpdatePrivateKey()
    ├─ 验证私钥
    ├─ 保存到配置文件
    └─ 通知条件变量 (不更新 security_)
    ↓
WaitForPrivateKeyUpdate() 返回
    ↓
重新调用 InitSecurity()
    ├─ 从配置文件读取私钥
    ├─ 创建并初始化 security_ 对象
    └─ 返回 kInitSuccess
    ↓
继续正常的初始化流程
    ├─ 初始化 TcpTransport
    ├─ 初始化 bls_mgr
    └─ 其他组件...
    ↓
程序正常运行
```

## 关键改进

1. **延迟 security 初始化**：在收到私钥之前不创建 `security_` 对象
2. **使用局部临时对象**：HTTP 服务器初始化时使用局部临时 security 对象
3. **重新调用 InitSecurity**：等待结束后重新调用 `InitSecurity()` 正确初始化
4. **区分初始设置和运行时更新**：`UpdatePrivateKey()` 根据场景采取不同行为

## 测试验证

### 测试步骤

1. 清空配置文件中的私钥
2. 启动程序
3. 观察日志，确认进入等待模式
4. 发送私钥更新请求
5. 验证程序继续初始化并正常运行
6. 检查没有段错误或其他崩溃

### 预期结果

- 程序不会在等待期间崩溃
- HTTP 服务器正常启动
- 接收私钥后程序继续初始化
- 所有组件按正确顺序初始化
- 没有访问未初始化的对象

## 相关文件

- `src/init/network_init.cc` - 主要修复
- `src/init/network_init.h` - 接口定义
- `PRIVATE_KEY_WAIT_FEATURE.md` - 功能说明
- `IMPLEMENTATION_SUMMARY.md` - 实现总结
