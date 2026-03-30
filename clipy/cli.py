import struct
import requests
import hashlib
import json
import time
from enum import IntEnum
import solcx
from solcx import compile_source, install_solc
import eth_abi

# Fix: Uniformly use keccak logic from Crypto.Hash to avoid conflicts with eth_utils
from Crypto.Hash import keccak
from eth_utils import to_checksum_address
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

# Preset environment
install_solc('0.8.30')

class StepType(IntEnum):
    kNormalFrom = 0                 # 用户直接转账 (发送方)
    kNormalTo = 1                   # 跨片确认交易 (发送方统计后的确认)
    kConsensusRootElectShard = 2    # 分片/根网络选举交易
    kConsensusRootTimeBlock = 3     # 时间块创建交易
    kConsensusCreateGenesisAcount = 4 # 创世账号创建交易
    kConsensusLocalTos = 5          # 跨片确认交易 (接收方累计后的确认)
    kCreateContract = 6             # 合约部署/创建交易
    kContractGasPrepayment = 7      # 设置合约调用预付 Gas
    kContractExcute = 8             # 执行合约调用
    kRootCreateAddress = 9          # 根网络创建新地址
    kStatistic = 12                 # 统计类交易
    kJoinElect = 13                 # 新节点参与选举交易
    kCreateLibrary = 14             # 创建公共合约库 (Library)
    kCross = 15                     # 跨片防丢块补齐交易
    kRootCross = 16                 # 根网络跨片防丢块补齐交易
    kPoolStatisticTag = 17          # 本轮交易池统计结束标记块

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

    def _uint64_to_bytes(self, val):
        return struct.pack('<Q', val)

    def _hex_to_bytes(self, hex_str):
        if hex_str.startswith('0x'): hex_str = hex_str[2:]
        return bytes.fromhex(hex_str)

    def get_address(self, private_key_hex):
        if private_key_hex.startswith('0x'): private_key_hex = private_key_hex[2:]
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        pub_key = sk.verifying_key.to_string("uncompressed")[1:] 
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
        step = int(step)
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
            print(f"transfer result: {resp.text}")
            if "SignatureInvalid" in resp.text:
                data["sign_v"] = "1"
                resp = requests.post(self.tx_url, data=data, timeout=5)
                print(f"1 transfer result: {resp.text}")
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
                    msg = resp.json().get("msg")
                    print(f"Transaction {tx_hash} receipt status: {MessageHandleStatus(status).name}, output: {msg}")
                    if status not in [MessageHandleStatus.kMessageHandle, MessageHandleStatus.kTxAccept]:
                        return status == MessageHandleStatus.kConsensusSuccess
            except: pass
            time.sleep(5)
        return False

    def query_contract(self, from_hex, to_hex, input_hex):
        try:
            resp = requests.post(self.query_contract_url, data={"from": from_hex, "address": to_hex, "input": input_hex}, timeout=5)
            if resp.status_code == 200:
                return resp.text
        except: pass
        return None

def install_solc_versions():
    try:
        solcx.install_solc("0.8.30")
        solcx.set_solc_version("0.8.30")
    except: pass
    
def compile_contract(source_code):
    compiler_params = {
        "evm_version": 'shanghai',
        "optimize": True,
        "optimize_runs": 200,
    }
    install_solc_versions()
    compiled_sol = solcx.compile_source(source_code, output_values=['abi', 'bin'], **compiler_params)
    return compiled_sol.popitem()[1]

def get_selector(signature):
    k = keccak.new(digest_bits=256)
    k.update(signature.encode('utf-8'))
    return k.digest()[:4].hex()

def calc_create2_address(sender, salt_hex, bytecode_hex):
    prefix = bytes.fromhex("ff")
    sender_bytes = bytes.fromhex(sender.replace('0x', ''))
    salt_bytes = bytes.fromhex(salt_hex.replace('0x', '').zfill(64))
    bytecode_bytes = bytes.fromhex(bytecode_hex.replace('0x', ''))
    k_code = keccak.new(digest_bits=256)
    k_code.update(bytecode_bytes)
    code_hash = k_code.digest()
    k_final = keccak.new(digest_bits=256)
    k_final.update(prefix + sender_bytes + salt_bytes + code_hash)
    raw_address = k_final.digest()
    return raw_address[-20:].hex().lower()

# ==========================================
# 修复后的 Library 编译逻辑
# ==========================================

def compile_contract_with_link(source_code, library_addresses=None):
    """
    :param library_addresses: {'MathLib': '0x...'}
    """
    lib_str = None
    if library_addresses:
        lib_parts = []
        for lib_name, addr in library_addresses.items():
            # 补全文件名占位符并确保 0x 前缀
            full_key = lib_name if ":" in lib_name else f"<stdin>:{lib_name}"
            clean_addr = addr if addr.startswith('0x') else '0x' + addr
            lib_parts.append(f"{full_key}={clean_addr}")
        lib_str = ",".join(lib_parts)

    compiler_params = {
        "evm_version": 'shanghai',
        "optimize": True,
        "optimize_runs": 200,
    }
    if lib_str:
        compiler_params["libraries"] = lib_str

    install_solc_versions()
    return solcx.compile_source(source_code, output_values=['abi', 'bin'], **compiler_params)

SETH_IP = "127.0.0.1" # 已根据日志更新 IP
SETH_PORT = 23001
PRIVATE_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"

def test_library():
    client = SethClient(SETH_IP, SETH_PORT)
    MY_ADDR = client.get_address(PRIVATE_KEY)

    # --- 1. 源码定义 (已移除 import 语句) ---
    full_source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    library MathLib {
        function add(uint256 a, uint256 b) public pure returns (uint256) {
            return a + b;
        }
    }

    contract Calculator {
        uint256 public lastResult;
        // 增加了 returns (uint256)
        function doAdd(uint256 a, uint256 b) public returns (uint256) {
            lastResult = MathLib.add(a, b);
            return lastResult; // 将结果返回
        }
    }
    """

    # --- 2. 部署 Library ---
    print("[Task Library] Compiling and Deploying MathLib...")
    # 提取库的单独代码进行编译
    lib_source = """
    pragma solidity ^0.8.0;
    library MathLib { function add(uint256 a, uint256 b) public pure returns (uint256) { return a+b; } }
    """
    lib_compile = compile_contract(lib_source)
    lib_bin = lib_compile['bin']
    
    LIB_TARGET = calc_create2_address(MY_ADDR, "01", lib_bin)
    # 使用 step=14 (kCreateLibrary) 部署公共库，并增加预付款
    tx_lib = client.send_transaction_auto(PRIVATE_KEY, LIB_TARGET, step=StepType.kCreateLibrary, contract_code=lib_bin, prepayment=10000000)
    
    if client.wait_for_receipt(tx_lib):
        print(f"✓ MathLib deployed at: 0x{LIB_TARGET}")
    else:
        print("✗ MathLib deployment failed, but proceeding to link...")

    # --- 3. 链接并部署主合约 ---
    print("[Task Contract] Linking MathLib and Deploying Calculator...")
    link_refs = {"MathLib": LIB_TARGET}
    
    # 编译主合约字符串
    contract_compiled = compile_contract_with_link(full_source, library_addresses=link_refs)
    calculator_interface = contract_compiled['<stdin>:Calculator']
    calc_bin = calculator_interface['bin']

    CALC_TARGET = calc_create2_address(MY_ADDR, "02", calc_bin)
    tx_calc = client.send_transaction_auto(PRIVATE_KEY, CALC_TARGET, step=StepType.kCreateContract, contract_code=calc_bin, prepayment=10000000)
    
    if client.wait_for_receipt(tx_calc):
        print(f"✓ Calculator deployed at: 0x{CALC_TARGET}")

        # --- 4. 调用测试 ---
        print("[Task Interaction] Calling Calculator.doAdd(10, 20)...")
        input_add = get_selector("doAdd(uint256,uint256)") + eth_abi.encode(['uint256', 'uint256'], [10, 20]).hex()
        tx_call = client.send_transaction_auto(PRIVATE_KEY, CALC_TARGET, step=StepType.kContractExcute, input_hex=input_add)
        client.wait_for_receipt(tx_call)
        
        raw_res = client.query_contract(MY_ADDR, CALC_TARGET, get_selector("lastResult()"))
        print(f"🔎 Result: {raw_res}")
    else:
        print("✗ Calculator deployment failed.")

if __name__ == "__main__":
    test_library()