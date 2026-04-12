#!/bin/bash

# 测试私钥等待功能的脚本

set -e

echo "=========================================="
echo "私钥等待功能测试脚本"
echo "=========================================="
echo ""

# 配置
CONFIG_FILE="conf/seth.conf"
BACKUP_FILE="conf/seth.conf.backup"
HTTP_PORT=8080
PRIVATE_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# 检查配置文件是否存在
if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 配置文件 $CONFIG_FILE 不存在"
    exit 1
fi

# 备份原配置文件
echo "1. 备份原配置文件..."
cp "$CONFIG_FILE" "$BACKUP_FILE"
echo "   已备份到: $BACKUP_FILE"
echo ""

# 清空私钥配置
echo "2. 清空配置文件中的私钥..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' 's/^prikey=.*/prikey=/' "$CONFIG_FILE"
else
    # Linux
    sed -i 's/^prikey=.*/prikey=/' "$CONFIG_FILE"
fi
echo "   私钥已清空"
echo ""

# 显示修改后的配置
echo "3. 当前配置文件中的私钥设置:"
grep "^prikey=" "$CONFIG_FILE" || echo "   prikey=(空)"
echo ""

echo "4. 启动程序（后台运行）..."
echo "   程序应该会等待私钥更新..."
echo "   请在另一个终端查看日志输出"
echo ""

# 提示用户启动程序
echo "=========================================="
echo "请执行以下步骤："
echo ""
echo "步骤 1: 在另一个终端启动程序"
echo "   ./seth -c $CONFIG_FILE"
echo ""
echo "步骤 2: 观察日志输出，应该看到类似信息："
echo "   [WARN] Private key is empty or not found in config, waiting for UpdatePrivateKey..."
echo "   [INFO] HTTP server started, waiting for private key update..."
echo "   [INFO] Waiting for private key update..."
echo ""
echo "步骤 3: 发送私钥更新请求（在本终端执行）"
echo "   按回车键继续..."
read -r

echo ""
echo "5. 发送私钥更新请求..."
RESPONSE=$(curl -s -X POST "http://localhost:$HTTP_PORT/update_private_key" \
  -d "private_key=$PRIVATE_KEY")

echo "   响应: $RESPONSE"
echo ""

# 检查响应
if echo "$RESPONSE" | grep -q '"status":0'; then
    echo "✓ 私钥更新成功！"
    echo ""
    echo "6. 检查程序是否继续运行..."
    echo "   请在程序终端查看日志，应该看到："
    echo "   [INFO] Private key received, resuming initialization..."
    echo "   [INFO] Private key updated successfully!"
else
    echo "✗ 私钥更新失败"
    echo "   响应: $RESPONSE"
fi

echo ""
echo "=========================================="
echo "测试完成"
echo ""
echo "恢复原配置文件："
echo "   cp $BACKUP_FILE $CONFIG_FILE"
echo "=========================================="
