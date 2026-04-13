#!/usr/bin/env python3
"""
测试私钥等待功能的Python脚本
"""

import requests
import time
import sys

def test_update_private_key(host="localhost", port=8080):
    """
    测试私钥更新功能
    
    Args:
        host: HTTP服务器地址
        port: HTTP服务器端口
    """
    # 测试用的私钥（十六进制编码，64个字符 = 32字节）
    test_private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    
    url = f"http://{host}:{port}/update_private_key"
    
    print("=" * 60)
    print("私钥等待功能测试")
    print("=" * 60)
    print()
    
    print(f"目标服务器: {url}")
    print(f"测试私钥: {test_private_key}")
    print()
    
    # 等待用户确认程序已启动
    print("请确保程序已启动并处于等待私钥状态")
    print("程序应该显示类似以下日志:")
    print("  [WARN] Private key is empty or not found in config, waiting for UpdatePrivateKey...")
    print("  [INFO] HTTP server started, waiting for private key update...")
    print("  [INFO] Waiting for private key update...")
    print()
    input("按回车键继续发送私钥更新请求...")
    print()
    
    # 发送私钥更新请求
    print("发送私钥更新请求...")
    try:
        response = requests.post(
            url,
            data={"private_key": test_private_key},
            timeout=10
        )
        
        print(f"HTTP状态码: {response.status_code}")
        print(f"响应内容: {response.text}")
        print()
        
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == 0:
                print("✓ 私钥更新成功！")
                print()
                print("请检查程序日志，应该看到:")
                print("  [INFO] Private key received, resuming initialization...")
                print("  [INFO] Private key updated successfully!")
                return True
            else:
                print(f"✗ 私钥更新失败: {result.get('msg', 'Unknown error')}")
                return False
        else:
            print(f"✗ HTTP请求失败，状态码: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("✗ 连接失败: 无法连接到服务器")
        print(f"   请确认程序已启动并监听在 {host}:{port}")
        return False
    except requests.exceptions.Timeout:
        print("✗ 请求超时")
        return False
    except Exception as e:
        print(f"✗ 发生错误: {e}")
        return False

def main():
    """主函数"""
    # 解析命令行参数
    host = "localhost"
    port = 8080
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    success = test_update_private_key(host, port)
    
    print()
    print("=" * 60)
    if success:
        print("测试完成 - 成功")
    else:
        print("测试完成 - 失败")
    print("=" * 60)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
