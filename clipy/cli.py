import struct
import requests
import hashlib
import json
import time
from Crypto.Hash import keccak
# 使用纯 Python 的 ecdsa 库
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_string_canonize

class SethClient:
    def __init__(self, host, port):
        self.base_url = f"http://{host}:{port}"
        self.tx_url = f"{self.base_url}/transaction"
        self.query_url = f"{self.base_url}/query_account"

    def _uint64_to_bytes(self, val):
        return struct.pack('<Q', val)

    def _hex_to_bytes(self, hex_str):
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        return bytes.fromhex(hex_str)

    def _derive_address_from_pubkey(self, pubkey_bytes_no_prefix):
        """
        根据公钥推导地址。
        假设规则与以太坊类似：Keccak256(Pubkey_64bytes) 的后 20 字节
        如果你的链规则不同，请修改此处。
        """
        k = keccak.new(digest_bits=256)
        k.update(pubkey_bytes_no_prefix)
        digest = k.digest()
        # 取后 20 字节作为地址
        address_bytes = digest[-20:]
        return address_bytes.hex()

    def get_latest_nonce(self, address_hex):
        """
        查询账户信息并获取最新 Nonce
        """
        print(f"[Client] Querying nonce for address: {address_hex}")
        try:
            # 构造请求，服务端 QueryAccount 接收 'address' 参数
            data = {"address": address_hex}
            resp = requests.post(self.query_url, data=data, timeout=5)
            
            if resp.status_code != 200:
                print(f"[Error] Query failed: {resp.text}")
                return 0 # 账户可能不存在，默认从 0 开始
            
            # 解析返回的 JSON
            # 服务端返回示例: {"address": "...", "balance": 1000, "nonce": 5, ...}
            # 注意：protobuf JSON 字段如果是默认值可能会被省略，需要处理
            try:
                account_info = resp.json()
                # 如果是空对象或没有 nonce 字段，说明是新账户，返回 0
                nonce = int(account_info.get("nonce", 0))
                print(f"[Client] Current Nonce on chain: {nonce}")
                return nonce
            except json.JSONDecodeError:
                print(f"[Client] Failed to parse JSON, assuming new account. Resp: {resp.text}")
                return 0

        except Exception as e:
            print(f"[Error] Get nonce error: {e}")
            return 0

    def compute_hash(self, nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, step, 
                     contract_code='', input_hex='', prepayment=0, key='', val=''):
        msg = bytearray()
        msg.extend(self._uint64_to_bytes(nonce))
        msg.extend(self._hex_to_bytes(pubkey_hex))
        msg.extend(self._hex_to_bytes(to_hex))
        msg.extend(self._uint64_to_bytes(amount))
        msg.extend(self._uint64_to_bytes(gas_limit))
        msg.extend(self._uint64_to_bytes(gas_price))
        msg.extend(self._uint64_to_bytes(step))
        if contract_code: msg.extend(self._hex_to_bytes(contract_code))
        if input_hex: msg.extend(self._hex_to_bytes(input_hex))
        if prepayment > 0: msg.extend(self._uint64_to_bytes(prepayment))
        if key:
            msg.extend(key.encode('utf-8'))
            if val: msg.extend(val.encode('utf-8'))
        
        k = keccak.new(digest_bits=256)
        k.update(msg)
        return k.digest()

    def send_transaction_auto(self, private_key_hex, to_hex, amount=0, 
                              gas_limit=50000, gas_price=1, step=0, shard_id=0,
                              contract_code='', input_hex='', prepayment=0,
                              key='', val=''):
        """
        自动流程：
        1. 从私钥推导公钥和地址
        2. 联网查询该地址的最新 Nonce
        3. Nonce + 1
        4. 签名并发送
        """
        
        # --- 1. 准备密钥 ---
        if private_key_hex.startswith('0x'):
            private_key_hex = private_key_hex[2:]
        
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        vk = sk.verifying_key
        
        # 导出未压缩公钥 (65 bytes: 04 + X + Y)
        pubkey_bytes_full = vk.to_string("uncompressed")
        pubkey_hex = pubkey_bytes_full.hex()
        
        # 推导地址 (用于查询 Nonce)
        # 获取不带 04 前缀的公钥字节 (64 bytes)
        pubkey_bytes_raw = pubkey_bytes_full[1:] 
        my_address_hex = self._derive_address_from_pubkey(pubkey_bytes_raw)
        
        # --- 2. 获取并递增 Nonce ---
        current_nonce = self.get_latest_nonce(my_address_hex)
        next_nonce = current_nonce + 1
        print(f"[Client] Using Next Nonce: {next_nonce}")

        # --- 3. 计算哈希 ---
        tx_hash = self.compute_hash(
            next_nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, step,
            contract_code, input_hex, prepayment, key, val
        )

        # --- 4. 签名 ---
        signature = sk.sign_digest_deterministic(
            tx_hash, 
            hashfunc=hashlib.sha256, 
            sigencode=sigencode_string_canonize
        )
        r_bytes = signature[0:32]
        s_bytes = signature[32:64]
        
        # 简单 Recovery ID 处理 (默认 0，失败重试 1)
        v_byte = 0

        # --- 5. 发送请求 ---
        data = {
            "nonce": str(next_nonce),
            "pubkey": pubkey_hex,
            "to": to_hex,
            "amount": str(amount),
            "gas_limit": str(gas_limit),
            "gas_price": str(gas_price),
            "shard_id": str(shard_id),
            "type": str(step),
            "sign_r": r_bytes.hex(),
            "sign_s": s_bytes.hex(),
            "sign_v": str(v_byte) 
        }

        # 可选参数
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment > 0: data["pepay"] = str(prepayment)
        if key: data["key"] = key
        if val: data["val"] = val

        print("[Client] Sending Transaction...")
        try:
            resp = requests.post(self.tx_url, data=data, timeout=5)
            print(f"[Server Response] {resp.status_code}: {resp.text}")
            
            # 自动重试 V=1
            if "SignatureInvalid" in resp.text or "verify signature failed" in resp.text:
                print("[Client] Signature rejected (V=0), retrying with V=1...")
                data["sign_v"] = "1"
                resp = requests.post(self.tx_url, data=data, timeout=5)
                print(f"[Server Response (Retry)] {resp.status_code}: {resp.text}")

        except Exception as e:
            print(f"[Error] Network error: {e}")

# ==========================================
# 运行测试
# ==========================================
if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 8888
    
    # 发送者私钥
    MY_PRIVATE_KEY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    # 接收者地址
    TO_ADDR = "1234567890abcdef1234567890abcdef12345678" 
    
    client = SethClient(HOST, PORT)
    
    # 调用自动 Nonce 接口
    client.send_transaction_auto(
        private_key_hex=MY_PRIVATE_KEY,
        to_hex=TO_ADDR,
        amount=5000,
        input_hex="112233" # 附带一些数据
    )