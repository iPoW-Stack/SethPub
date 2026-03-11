import struct
import requests
import hashlib
import json
import time
from enum import IntEnum
import solcx
from solcx import compile_source, install_solc
import eth_abi

# 修复：统一使用 Crypto.Hash 中的 keccak 逻辑，避免与 eth_utils 冲突
from Crypto.Hash import keccak
from eth_utils import to_checksum_address
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

# 预设环境
install_solc('0.8.30')

class MessageHandleStatus(IntEnum):
    kConsensusSuccess = 0
    kMessageHandle = 1
    kMessageHandleError = 2
    kTxAccept = 3
    kTxInvalidSignature = 4
    kTxInvalidAddress = 5
    kTxPoolFullReject = 6
    kTxUserNonceInvalid = 7
    kUnknown = 8
    kRequestInvalid = 9
    kNotExists = 10

class SethClient:
    def __init__(self, host, port):
        self.base_url = f"http://{host}:{port}"
        self.tx_url = f"{self.base_url}/transaction"
        self.query_url = f"{self.base_url}/query_account"
        self.receipt_url = f"{self.base_url}/transaction_receipt"
        self.query_contract_url = f"{self.base_url}/query_contract"

    # --- 工具函数 ---
    def _uint64_to_bytes(self, val):
        return struct.pack('<Q', val)

    def _hex_to_bytes(self, hex_str):
        if hex_str.startswith('0x'): hex_str = hex_str[2:]
        return bytes.fromhex(hex_str)

    def get_address(self, private_key_hex):
        """从私钥推导地址"""
        if private_key_hex.startswith('0x'): private_key_hex = private_key_hex[2:]
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        pub_key = sk.verifying_key.to_string("uncompressed")[1:] # 去除 04 前缀
        
        # 修复：使用 keccak.new 替代模块直接调用
        k = keccak.new(digest_bits=256)
        k.update(pub_key)
        return k.digest()[-20:].hex()

    def get_nonce(self, address):
        try:
            resp = requests.post(self.query_url, data={"address": address}, timeout=5)
            return int(resp.json().get("nonce", 0)) if resp.status_code == 200 else 0
        except: return 0

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
        
        # 修复：使用 keccak.new
        k = keccak.new(digest_bits=256)
        k.update(msg)
        return k.digest()

    def send_transaction_auto(self, private_key_hex, to_hex, amount=0,
                              gas_limit=5000000, gas_price=1, step=0, shard_id=0,
                              contract_code='', input_hex='', prepayment=0,
                              key='', val=''):
        if private_key_hex.startswith('0x'): private_key_hex = private_key_hex[2:]
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        pubkey_hex = sk.verifying_key.to_string("uncompressed").hex()
        my_addr = self.get_address(private_key_hex)
        if step == 8:
            my_addr = to_hex + my_addr
            
        nonce = self.get_nonce(my_addr) + 1
        tx_hash = self.compute_hash(nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, 
                                    step, contract_code, input_hex, prepayment, key, val)

        signature = sk.sign_digest_deterministic(tx_hash, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)
        
        data = {
            "nonce": str(nonce), "pubkey": pubkey_hex, "to": to_hex, "amount": str(amount),
            "gas_limit": str(gas_limit), "gas_price": str(gas_price), "shard_id": str(shard_id),
            "type": str(step), "sign_r": signature[0:32].hex(), "sign_s": signature[32:64].hex(), "sign_v": "0"
        }
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment > 0: data["pepay"] = str(prepayment)
        if key: data["key"] = key
        if val: data["val"] = val

        try:
            resp = requests.post(self.tx_url, data=data, timeout=5)
            print(f"transfer result: ${resp.text}")
            if "SignatureInvalid" in resp.text:
                data["sign_v"] = "1"
                resp = requests.post(self.tx_url, data=data, timeout=5)
                print(f"1 transfer result: ${resp.text}")
            return tx_hash.hex()
        except Exception as e:
            print(f"Send TX Error: {e}")
            return None

    def wait_for_receipt(self, tx_hash, timeout=15):
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}, timeout=2)
                if resp.status_code == 200:
                    status = resp.json().get("status")
                    print(f"Transaction {tx_hash} receipt status: {MessageHandleStatus(status).name}")
                    if status not in [MessageHandleStatus.kMessageHandle, MessageHandleStatus.kTxAccept]:
                        return True
            except: pass
            time.sleep(1)
        return False

    def query_contract(self, from_hex, to_hex, input_hex):
        try:
            resp = requests.post(self.query_contract_url, data={"from": from_hex, "address": to_hex, "input": input_hex}, timeout=5)
            if resp.status_code == 200:
                return resp.json().get("output", "")
        except: pass
        return None

def install_solc_versions():
    """安装多个solc版本"""
    try:
        # 定义要安装的版本
        versions = ["0.8.30"]
        for version in versions:
            try:
                solcx.install_solc(version)
            except Exception as e:
                return False

        # 设置默认版本
        solcx.set_solc_version("0.8.30")

    except Exception as e:
        return False
    
# --- 全局编译工具 ---
def compile_contract(source_code):
    compiler_params = {
        "evm_version": 'shanghai',
        "optimize": True,
        "optimize_runs": 200,
        "via_ir": True,           # 如果有需要可开启
    }

    install_solc_versions()
    compiled_sol = solcx.compile_source(
        source_code,
        output_values=['abi', 'bin'],
        **compiler_params
    )

    return compiled_sol.popitem()[1]

def get_selector(signature):
    k = keccak.new(digest_bits=256)
    k.update(signature.encode('utf-8'))
    return k.digest()[:4].hex()

def calc_create2_address(sender, salt_hex, bytecode_hex):
    # 修复：使用 keccak.new 规范计算过程
    prefix = bytes.fromhex("ff")
    sender_bytes = bytes.fromhex(sender.replace('0x', ''))
    
    # 修复：salt 必须补齐为 32 字节 (64位 hex)
    salt_bytes = bytes.fromhex(salt_hex.replace('0x', '').zfill(64))
    bytecode_bytes = bytes.fromhex(bytecode_hex.replace('0x', ''))

    # 计算 bytecode 的哈希
    k_code = keccak.new(digest_bits=256)
    k_code.update(bytecode_bytes)
    code_hash = k_code.digest()

    # 计算最终地址哈希
    k_final = keccak.new(digest_bits=256)
    k_final.update(prefix + sender_bytes + salt_bytes + code_hash)
    raw_address = k_final.digest()
    
    # 返回后 20 字节
    return raw_address[-20:].hex().lower()

# ==========================================
# 完整闭环测试
# ==========================================
if __name__ == "__main__":
    client = SethClient("35.197.170.240", 23001)
    MY_PK = "c75f8d9b2a6bc0fe68eac7fef67c6b6f7c4f85163d58829b59110ff9e9210848"
    OTHER_ADDR = "1234567890abcdef1234567890abcdef12345678"

    # --- 1. 转账 ---
    print("[Task 1] Sending standard transfer...")
    tx_transfer = client.send_transaction_auto(MY_PK, OTHER_ADDR, amount=1000)
    if client.wait_for_receipt(tx_transfer):
        print("✓ Transfer success.")

    # 1. 编译合约
    contract_source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    contract SimpleStorage {
        string private message;
        constructor(string memory _initialMessage) { message = _initialMessage; }
        function setMessage(string memory _newMessage) public { message = _newMessage; }
        function getMessage() public view returns (string memory) { return message; }
    }
    """
    print("[Step 1] Compiling...")
    interface = compile_contract(contract_source)
    
    # 2. 部署合约 (带构造函数参数)
    print("[Step 2] Deploying...")
    # 构造函数参数编码：'Hello Seth!'
    constructor_args = eth_abi.encode(['string'], ["Hello Seth!"]).hex()
    deploy_code = interface['bin'] + constructor_args
    
    # 这里的 CONTRACT_ADDR 如果是固定推导的请替换，否则部署后通常从收据获取
    # 为演示方便，沿用你的固定地址
    TARGET_CONTRACT = calc_create2_address(client.get_address(MY_PK), "00", deploy_code)
    
    tx_deploy = client.send_transaction_auto(MY_PK, TARGET_CONTRACT, step=6, contract_code=deploy_code, prepayment=10000000)
    client.wait_for_receipt(tx_deploy, timeout=30)
    print(f"✓ Contract deployed at: {TARGET_CONTRACT}")

    # 3. 修改数据 (调用 setMessage)
    print("[Step 3] Updating message...")
    new_text = "Updated at " + time.ctime()
    selector_set = get_selector("setMessage(string)")
    input_set = selector_set + eth_abi.encode(['string'], [new_text]).hex()
    
    tx_update = client.send_transaction_auto(MY_PK, TARGET_CONTRACT, step=8, input_hex=input_set)
    client.wait_for_receipt(tx_update)
    print(f"✓ Message updated to: {new_text}")

    # 4. 查询数据 (调用 getMessage)
    print("[Step 4] Querying message...")
    selector_get = get_selector("getMessage()")
    # 注意：getMessage() 没有参数，input 只有 selector
    raw_output = client.query_contract(client.get_address(MY_PK), TARGET_CONTRACT, selector_get)
    
    if raw_output:
        # 去掉可能存在的 0x 前缀并解码
        clean_hex = raw_output.replace("0x", "")
        decoded = eth_abi.decode(['string'], bytes.fromhex(clean_hex))
        print(f"🔎 Current Message in Contract: {decoded[0]}")
    else:
        print("✗ Query failed.")