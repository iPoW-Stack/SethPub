import struct
import requests
import hashlib
import json
import time
from enum import IntEnum
from solcx import compile_source, install_solc
import eth_abi
from eth_utils import keccak, to_checksum_address
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
        # 原有的 key/val 逻辑保留
        if key:
            msg.extend(key.encode('utf-8'))
            if val: msg.extend(val.encode('utf-8'))
        
        k = keccak.new(digest_bits=256)
        k.update(msg)
        return k.digest()

    # --- 核心交易接口 ---
    def send_transaction_auto(self, private_key_hex, to_hex, amount=0,
                              gas_limit=50000, gas_price=1, step=0, shard_id=0,
                              contract_code='', input_hex='', prepayment=0,
                              key='', val=''):
        """通用交易接口：支持转账、部署、合约调用"""
        if private_key_hex.startswith('0x'): private_key_hex = private_key_hex[2:]
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        pubkey_hex = sk.verifying_key.to_string("uncompressed").hex()
        my_addr = self.get_address(private_key_hex)
        
        nonce = self.get_nonce(my_addr) + 1
        tx_hash = self.compute_hash(nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, 
                                    step, contract_code, input_hex, prepayment, key, val)

        # 签名
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
            # 自动重试 V=1
            if "SignatureInvalid" in resp.text:
                data["sign_v"] = "1"
                resp = requests.post(self.tx_url, data=data, timeout=5)
            return tx_hash.hex()
        except Exception as e:
            print(f"Send TX Error: {e}")
            return None

    def wait_for_receipt(self, tx_hash, timeout=15):
        """轮询收据直到成功或超时"""
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}, timeout=2)
                if resp.status_code == 200:
                    status = resp.json().get("status")
                    if status not in [MessageHandleStatus.kMessageHandle, MessageHandleStatus.kTxAccept]:
                        return True
            except: pass
            time.sleep(1)
        return False

    def query_contract(self, to_hex, input_hex):
        """只读合约调用"""
        try:
            resp = requests.post(self.query_contract_url, data={"to": to_hex, "input": input_hex}, timeout=5)
            if resp.status_code == 200:
                return resp.json().get("output", "")
        except: pass
        return None

# --- 全局编译工具 ---
def compile_contract(source):
    # 使用 via_ir 解决 stack too deep，启用 200 次优化
    compiled = compile_source(source, output_values=['abi', 'bin'], solc_version='0.8.30', 
                             via_ir=True, optimize=True, optimize_runs=200)
    return compiled.popitem()[1]

def get_selector(signature):
    k = keccak.new(digest_bits=256)
    k.update(signature.encode('utf-8'))
    return k.digest()[:4].hex()

def calc_create2_address(sender, salt, bytecode):
    prefix = bytes.fromhex("ff")
    sender_bytes = bytes.fromhex(sender)
    salt_bytes = bytes.fromhex(salt)
    bytecode_hash = keccak(bytes.fromhex(bytecode))

    raw_address = keccak(prefix + sender_bytes + salt_bytes + bytecode_hash)
    return to_checksum_address(raw_address[12:].hex())[2:].lower()

# ==========================================
# 完整闭环测试
# ==========================================
if __name__ == "__main__":
    client = SethClient("35.197.170.240", 23001)
    MY_PK = "c75f8d9b2a6bc0fe68eac7fef67c6b6f7c4f85163d58829b59110ff9e9210848"
    OTHER_ADDR = "1234567890abcdef1234567890abcdef12345678"

    # --- 1. 原有的普通转账功能 ---
    print("[Task 1] Sending standard transfer...")
    tx_transfer = client.send_transaction_auto(MY_PK, OTHER_ADDR, amount=1000)
    if client.wait_for_receipt(tx_transfer):
        print("✓ Transfer success.")

    # --- 2. 编译并部署合约 ---
    contract_source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    contract DataRegistry {
        struct Record { string did; string loc; uint8 mod; }
        mapping(string => Record) public records;
        function register(string calldata _did, string calldata _loc, uint8 _mod) external {
            records[_did] = Record(_did, _loc, _mod);
        }

        function get(string calldata _did) external view returns (string memory, string memory, uint8) {
            Record memory r = records[_did];
            return (r.did, r.loc, r.mod);
        }
    }
    """
    print("[Task 2] Compiling and Deploying contract...")
    interface = compile_contract(contract_source)
    
    CONTRACT_ADDR = calc_create2_address(client.get_address(MY_PK), "00", interface['bin'])
    # 部署交易 (to 为零地址)
    tx_deploy = client.send_transaction_auto(MY_PK, CONTRACT_ADDR, step=6, contract_code=interface['bin'], gas_limit=3000000)
    client.wait_for_receipt(tx_deploy, timeout=60)
    
    # 注意：实际需从 receipt 中解析 contract_address，此处演示硬编码或预测

    # --- 3. 调用合约写入 (Execute) ---
    print("[Task 3] Writing to contract...")
    did_key = f"did:seth:{int(time.time())}"
    sel_reg = get_selector("register(string,string,uint8)")
    encoded_input = sel_reg + eth_abi.encode(['string', 'string', 'uint8'], [did_key, "ipfs://location", 1]).hex()
    
    tx_reg = client.send_transaction_auto(MY_PK, CONTRACT_ADDR, step=8, input_hex=encoded_input, gas_limit=1000000)
    if client.wait_for_receipt(tx_reg, timeout=60):
        print("✓ Data registered.")

    # --- 4. 调用合约查询 (Query) ---
    print("[Task 4] Querying contract state...")
    sel_get = get_selector("get(string)")
    query_input = sel_get + eth_abi.encode(['string'], [did_key]).hex()
    
    raw_output = client.query_contract(CONTRACT_ADDR, query_input)
    if raw_output:
        # 去掉前缀并解析
        clean_hex = raw_output.replace("0x", "")
        decoded = eth_abi.decode(['string', 'string', 'uint8'], bytes.fromhex(clean_hex))
        print(f"🔎 Result Found -> DID: {decoded[0]}, Loc: {decoded[1]}, Mod: {decoded[2]}")
    else:
        print("✗ Query returned no data.")