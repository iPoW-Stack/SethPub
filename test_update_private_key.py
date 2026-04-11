#!/usr/bin/env python3
"""
测试私钥更新接口
"""

import requests
import json
import sys
from urllib3.exceptions import InsecureRequestWarning

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def update_private_key(server_url, private_key_hex):
    """
    更新服务器的私钥
    
    Args:
        server_url: 服务器地址，例如 https://localhost:8080
        private_key_hex: 新的私钥（十六进制字符串）
    
    Returns:
        响应结果
    """
    url = f"{server_url}/update_private_key"
    
    # 准备请求数据
    data = {
        "private_key": private_key_hex
    }
    
    try:
        # 发送 POST 请求
        response = requests.post(
            url,
            data=data,
            verify=False,  # 跳过 SSL 证书验证（自签名证书）
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            print(f"❌ HTTP 错误: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求失败: {e}")
        return None

def main():
    """主函数"""
    print("=" * 60)
    print("私钥更新测试工具")
    print("=" * 60)
    
    # 配置
    SERVER_URL = "https://localhost:8080"
    
    # 示例私钥（请替换为实际的私钥）
    # 这是一个 32 字节（64 个十六进制字符）的示例私钥
    EXAMPLE_PRIVATE_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    
    if len(sys.argv) > 1:
        # 从命令行参数获取私钥
        private_key = sys.argv[1]
    else:
        # 使用示例私钥
        print(f"\n⚠️  警告: 未提供私钥参数，使用示例私钥")
        print(f"用法: python3 {sys.argv[0]} <private_key_hex>")
        print(f"\n使用示例私钥进行测试...")
        private_key = EXAMPLE_PRIVATE_KEY
    
    # 验证私钥格式
    if len(private_key) != 64 and len(private_key) != 128:
        print(f"❌ 错误: 私钥长度不正确")
        print(f"   期望: 64 个字符（32 字节原始私钥）或 128+ 字符（加密私钥）")
        print(f"   实际: {len(private_key)} 个字符")
        return 1
    
    try:
        # 验证是否为有效的十六进制字符串
        int(private_key, 16)
    except ValueError:
        print(f"❌ 错误: 私钥不是有效的十六进制字符串")
        return 1
    
    print(f"\n服务器地址: {SERVER_URL}")
    print(f"私钥长度: {len(private_key)} 字符")
    print(f"私钥前缀: {private_key[:16]}...")
    print(f"\n正在更新私钥...")
    
    # 调用更新接口
    result = update_private_key(SERVER_URL, private_key)
    
    if result:
        print(f"\n{'=' * 60}")
        print("响应结果:")
        print(f"{'=' * 60}")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        if result.get("status") == 0:
            print(f"\n✅ 私钥更新成功！")
            return 0
        else:
            print(f"\n❌ 私钥更新失败: {result.get('msg', 'Unknown error')}")
            return 1
    else:
        print(f"\n❌ 请求失败")
        return 1

if __name__ == "__main__":
    sys.exit(main())
