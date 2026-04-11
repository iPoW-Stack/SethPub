# HTTP to HTTPS 迁移检查清单

## 代码修改 ✅

- [x] 创建 `src/init/uws_adapter.h` 适配器
- [x] 修改 `src/init/http_handler.h` 头文件
- [x] 修改 `src/init/http_handler.cc` 实现文件
- [x] 更新 `CMakeLists.txt` 添加依赖
- [x] 移除所有 httplib 引用
- [x] 替换所有 `httplib::Request` 为 `UWSRequest`
- [x] 替换所有 `httplib::Response` 为 `UWSResponse`
- [x] 重写 `Run()` 方法使用 uWS::SSLApp
- [x] 重写 `Init()` 方法配置证书

## SSL/TLS 配置 ✅

- [x] 生成自签名证书 (`server-cert.pem`)
- [x] 生成私钥 (`server-key.pem`)
- [x] 设置证书文件权限
- [x] 配置证书路径

## API 端点迁移 ✅

- [x] `/transaction` - 标准交易
- [x] `/oqs_transaction` - OQS 交易
- [x] `/gm_transaction` - 国密交易
- [x] `/query_contract` - 查询合约
- [x] `/abi_query_contract` - ABI 查询
- [x] `/query_account` - 查询账户
- [x] `/query_init` - 初始化查询
- [x] `/get_proxy_reenc_info` - 代理重加密
- [x] `/ars_create_sec_keys` - ARS 密钥
- [x] `/accounts_valid` - 账户验证
- [x] `/commit_gid_valid` - GID 验证
- [x] `/prefund_valid` - 预付款验证
- [x] `/get_block_with_gid` - GID 获取区块
- [x] `/get_blocks` - 获取区块
- [x] `/get_latest_pool_info` - 池信息
- [x] `/get_block_with_hash` - 哈希获取区块
- [x] `/transaction_receipt` - 交易回执
- [x] `/get_seckey_and_encrypt_data` - 加密数据
- [x] `/proxy_decrypt` - 代理解密

## 文档和工具 ✅

- [x] `HTTPS_MIGRATION.md` - 迁移说明
- [x] `BUILD_GUIDE.md` - 编译指南
- [x] `MIGRATION_SUMMARY.md` - 迁移总结
- [x] `CHECKLIST.md` - 本检查清单
- [x] `install_uwebsockets.sh` - 安装脚本
- [x] `quick_start.sh` - 快速启动脚本
- [x] `test_https_client.py` - 测试客户端

## 编译和测试 ⏳

- [ ] 安装 uWebSockets 依赖
- [ ] 运行 CMake 配置
- [ ] 编译项目
- [ ] 检查编译警告
- [ ] 检查链接错误
- [ ] 运行基本测试
- [ ] 验证所有 API 端点
- [ ] 性能基准测试

## 部署准备 ⏳

- [ ] 准备生产环境证书
- [ ] 配置防火墙规则
- [ ] 设置 systemd 服务
- [ ] 配置日志轮转
- [ ] 设置监控告警
- [ ] 准备回滚方案
- [ ] 编写运维文档

## 安全检查 ⏳

- [ ] SSL/TLS 配置审计
- [ ] 证书有效期检查
- [ ] 密码套件配置
- [ ] 访问控制测试
- [ ] 渗透测试
- [ ] 依赖库安全扫描

## 性能优化 ⏳

- [ ] 压力测试
- [ ] 并发测试
- [ ] 内存泄漏检查
- [ ] CPU 使用率分析
- [ ] 网络延迟测试
- [ ] 系统参数调优

## 客户端更新 ⏳

- [ ] 更新客户端 URL (HTTP → HTTPS)
- [ ] 配置证书验证
- [ ] 更新 API 文档
- [ ] 通知相关团队
- [ ] 提供迁移指南

## 监控和日志 ⏳

- [ ] 配置日志收集
- [ ] 设置性能监控
- [ ] 配置错误告警
- [ ] 设置健康检查
- [ ] 配置访问日志

## 备份和恢复 ⏳

- [ ] 备份原始代码
- [ ] 备份配置文件
- [ ] 备份数据库
- [ ] 测试恢复流程
- [ ] 文档化恢复步骤

## 上线检查 ⏳

- [ ] 代码审查完成
- [ ] 测试环境验证
- [ ] 预生产环境验证
- [ ] 上线计划制定
- [ ] 回滚计划准备
- [ ] 团队培训完成
- [ ] 文档更新完成

## 上线后验证 ⏳

- [ ] 服务正常启动
- [ ] 所有端点可访问
- [ ] 性能指标正常
- [ ] 错误率正常
- [ ] 日志正常输出
- [ ] 监控数据正常
- [ ] 客户端连接正常

## 后续优化 ⏳

- [ ] 添加 HTTP/2 支持
- [ ] 实现请求限流
- [ ] 添加缓存机制
- [ ] 优化数据库查询
- [ ] 实现连接池
- [ ] 添加负载均衡

---

## 使用说明

### 标记说明
- ✅ 已完成
- ⏳ 待完成
- ❌ 失败/阻塞
- ⚠️ 需要注意

### 更新方法
```bash
# 完成某项后，将 [ ] 改为 [x]
# 例如：
- [ ] 安装 uWebSockets 依赖
# 改为：
- [x] 安装 uWebSockets 依赖
```

### 优先级
1. **P0 (必须)**: 代码修改、编译测试
2. **P1 (重要)**: 安全检查、性能测试
3. **P2 (建议)**: 监控日志、后续优化

---

**最后更新**: 2026-04-12  
**当前状态**: 代码迁移完成，待编译测试
