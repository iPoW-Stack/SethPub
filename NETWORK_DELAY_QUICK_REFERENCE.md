# 网络延迟注入 - 快速参考

## 启动节点

### 默认配置 (公网模拟: 50ms RTT)

```bash
./start_cmd.sh <local_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard>
```

默认参数:
- SETH_NETWORK_ENABLED=1 (启用)
- SETH_NETWORK_DELAY_MS=25 (单向 25ms)
- SETH_NETWORK_JITTER_MS=10 (抖动 10ms)
- SETH_NETWORK_LOSS_RATE=0.0001 (丢包率 0.01%)

### 自定义配置

#### 局域网模拟 (2ms RTT)

```bash
export SETH_NETWORK_ENABLED=1
export SETH_NETWORK_DELAY_MS=1
export SETH_NETWORK_JITTER_MS=0
export SETH_NETWORK_LOSS_RATE=0

./start_cmd.sh <local_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard>
```

#### 高延迟网络 (100ms RTT)

```bash
export SETH_NETWORK_ENABLED=1
export SETH_NETWORK_DELAY_MS=50
export SETH_NETWORK_JITTER_MS=20
export SETH_NETWORK_LOSS_RATE=0.001

./start_cmd.sh <local_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard>
```

#### 禁用网络模拟

```bash
export SETH_NETWORK_ENABLED=0

./start_cmd.sh <local_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard>
```

## 环境变量说明

| 变量 | 说明 | 默认值 | 范围 |
|------|------|--------|------|
| SETH_NETWORK_ENABLED | 启用/禁用 | 1 | 0-1 |
| SETH_NETWORK_DELAY_MS | 单向延迟 (ms) | 25 | 0-1000 |
| SETH_NETWORK_JITTER_MS | 抖动 (ms) | 10 | 0-100 |
| SETH_NETWORK_LOSS_RATE | 丢包率 | 0.0001 | 0-1 |

## 验证

### 查看启动日志

```bash
grep "Network simulation" /root/seths/s*/seth.log
```

### 查看网络参数

```bash
echo "SETH_NETWORK_ENABLED=$SETH_NETWORK_ENABLED"
echo "SETH_NETWORK_DELAY_MS=$SETH_NETWORK_DELAY_MS"
echo "SETH_NETWORK_JITTER_MS=$SETH_NETWORK_JITTER_MS"
echo "SETH_NETWORK_LOSS_RATE=$SETH_NETWORK_LOSS_RATE"
```

## 实现文件

- `start_cmd.sh`: 启动脚本 (已修改)
- `src/transport/network_delay_simulator.h`: 网络延迟模拟器
- `src/transport/uv_tcp_transport.h`: Transport 层头文件 (已修改)
- `src/transport/uv_tcp_transport.cc`: Transport 层实现 (已修改)

## 相关文档

- `APP_LAYER_NETWORK_DELAY_USAGE.md`: 详细使用指南
- `APP_LAYER_NETWORK_DELAY_IMPLEMENTATION.md`: 实现指南
- `cleanup_tc_rules.sh`: 清理 TC 规则脚本
