import requests
import json

class SethHttpClient:
    def __init__(self, host, port):
        self.base_url = f"http://{host}:{port}"

    def get_blocks(self, network, pool_index, height, count=1):
        """
        对应 C++ 的 svr.Post("/get_blocks", GetBlocks)
        """
        url = f"{self.base_url}/get_blocks"

        # 构造 POST 参数
        # 注意：C++ 代码中使用 get_param_value，这通常对应表单格式 (data=payload)
        payload = {
            "network": str(network),
            "pool_index": str(pool_index),
            "height": str(height),
            "count": str(count)
        }

        try:
            # 发送 POST 请求
            # 使用 data=payload 发送 application/x-www-form-urlencoded 格式
            response = requests.post(url, data=payload, timeout=10)

            print(f"请求状态码: {response.status_code}")

            if response.status_code == 200:
                # 尝试解析 JSON
                try:
                    return response.json()
                except:
                    # 如果返回的是纯文本
                    return response.text
            else:
                return f"Error: {response.text}"

        except requests.exceptions.RequestException as e:
            return f"Connection Failed: {e}"

# --- 使用示例 ---
if __name__ == "__main__":
    # 配置你的服务器 IP 和端口（对应 Init 函数中的 ip, port）
    client = SethHttpClient("104.198.109.193", 23080)

    # 调用接口
    # 假设获取 network 3, pool 0, 从高度 1000 开始的 5 个块
    res = client.get_blocks(network=3, pool_index=13, height=0, count=32)

    # 格式化输出结果
    if isinstance(res, dict):
        print(json.dumps(res, indent=4, ensure_ascii=False))
    else:
        print(res)
