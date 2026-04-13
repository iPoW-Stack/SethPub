#!/usr/bin/env python3
"""
HTTPS 客户端测试脚本
用于测试迁移到 uWebSockets + HTTPS 后的服务器
"""

import requests
import json
import sys
from urllib3.exceptions import InsecureRequestWarning

# 禁用 SSL 警告（仅用于自签名证书测试）
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class HTTPSClient:
    def __init__(self, base_url, verify_ssl=False):
        """
        初始化 HTTPS 客户端
        
        Args:
            base_url: 服务器基础 URL，例如 https://localhost:8080
            verify_ssl: 是否验证 SSL 证书，自签名证书设为 False
        """
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
    
    def post(self, endpoint, data=None, json_data=None):
        """
        发送 POST 请求
        
        Args:
            endpoint: API 端点，例如 /query_init
            data: 表单数据
            json_data: JSON 数据
        
        Returns:
            响应对象
        """
        url = f"{self.base_url}{endpoint}"
        try:
            if json_data:
                response = self.session.post(
                    url, 
                    json=json_data, 
                    verify=self.verify_ssl,
                    timeout=10
                )
            else:
                response = self.session.post(
                    url, 
                    data=data, 
                    verify=self.verify_ssl,
                    timeout=10
                )
            return response
        except requests.exceptions.RequestException as e:
            print(f"❌ 请求失败: {e}")
            return None

def test_query_init(client):
    """测试 /query_init 端点"""
    print("\n测试 1: /query_init")
    print("-" * 50)
    response = client.post("/query_init")
    if response and response.status_code == 200:
        print(f"✓ 状态码: {response.status_code}")
        print(f"✓ 响应: {response.text}")
        return True
    else:
        print(f"✗ 失败: {response.status_code if response else 'No response'}")
        return False

def test_query_account(client):
    """测试 /query_account 端点"""
    print("\n测试 2: /query_account")
    print("-" * 50)
    # 使用示例地址（需要替换为实际存在的地址）
    test_address = "0" * 40  # 40个0的十六进制地址
    response = client.post("/query_account", data={"address": test_address})
    if response:
        print(f"✓ 状态码: {response.status_code}")
        print(f"✓ 响应: {response.text[:200]}...")  # 只显示前200字符
        return True
    else:
        print("✗ 请求失败")
        return False

def test_transaction(client):
    """测试 /transaction 端点（需要有效参数）"""
    print("\n测试 3: /transaction")
    print("-" * 50)
    # 这里只是测试连接，实际使用需要有效的交易参数
    test_data = {
        "nonce": "1",
        "pubkey": "0" * 130,  # 示例公钥
        "to": "0" * 40,
        "amount": "1000",
        "gas_limit": "21000",
        "gas_price": "1",
        "sign_r": "0" * 64,
        "sign_s": "0" * 64,
        "sign_v": "0",
        "shard_id": "3",
        "type": "0"
    }
    response = client.post("/transaction", data=test_data)
    if response:
        print(f"✓ 状态码: {response.status_code}")
        print(f"✓ 响应: {response.text}")
        return True
    else:
        print("✗ 请求失败")
        return False

def test_get_blocks(client):
    """测试 /get_blocks 端点"""
    print("\n测试 4: /get_blocks")
    print("-" * 50)
    test_data = {
        "network": "3",
        "pool_index": "0",
        "height": "1",
        "count": "1"
    }
    response = client.post("/get_blocks", data=test_data)
    if response:
        print(f"✓ 状态码: {response.status_code}")
        try:
            json_response = response.json()
            print(f"✓ JSON 响应: {json.dumps(json_response, indent=2)[:300]}...")
        except:
            print(f"✓ 响应: {response.text[:200]}...")
        return True
    else:
        print("✗ 请求失败")
        return False

def main():
    """主测试函数"""
    # 配置
    SERVER_URL = "https://localhost:8080"  # 修改为实际服务器地址和端口
    
    print("=" * 50)
    print("HTTPS 服务器测试")
    print("=" * 50)
    print(f"服务器地址: {SERVER_URL}")
    print(f"SSL 验证: 关闭（自签名证书）")
    
    # 创建客户端
    client = HTTPSClient(SERVER_URL, verify_ssl=False)
    
    # 运行测试
    tests = [
        test_query_init,
        test_query_account,
        test_transaction,
        test_get_blocks
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func(client)
            results.append(result)
        except Exception as e:
            print(f"✗ 测试异常: {e}")
            results.append(False)
    
    # 总结
    print("\n" + "=" * 50)
    print("测试总结")
    print("=" * 50)
    passed = sum(results)
    total = len(results)
    print(f"通过: {passed}/{total}")
    
    if passed == total:
        print("✓ 所有测试通过！")
        return 0
    else:
        print("✗ 部分测试失败")
        return 1

if __name__ == "__main__":
    sys.exit(main())
