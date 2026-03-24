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
    """
    Shardora (Seth) 协议交易步骤类型枚举
    用于 send_transaction 中的 step 参数
    """
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

    # --- Utility Functions ---
    def _uint64_to_bytes(self, val):
        return struct.pack('<Q', val)

    def _hex_to_bytes(self, hex_str):
        if hex_str.startswith('0x'): hex_str = hex_str[2:]
        return bytes.fromhex(hex_str)

    def get_address(self, private_key_hex):
        """Derive address from private key"""
        if private_key_hex.startswith('0x'): private_key_hex = private_key_hex[2:]
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        pub_key = sk.verifying_key.to_string("uncompressed")[1:] # Remove 04 prefix
        
        # Fix: Use keccak.new instead of direct module call
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
        
        # Fix: Use keccak.new
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
                return resp.text
        except: pass
        return None

def install_solc_versions():
    """Install multiple solc versions"""
    try:
        # Define versions to install
        versions = ["0.8.30"]
        for version in versions:
            try:
                solcx.install_solc(version)
            except Exception as e:
                return False

        # Set default version
        solcx.set_solc_version("0.8.30")

    except Exception as e:
        return False
    
# --- Global Compilation Utilities ---
def compile_contract(source_code):
    compiler_params = {
        "evm_version": 'shanghai',
        "optimize": True,
        "optimize_runs": 200,
        "via_ir": True,           # Enable via_ir if necessary
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
    # Fix: Use keccak.new to standardize the calculation process
    prefix = bytes.fromhex("ff")
    sender_bytes = bytes.fromhex(sender.replace('0x', ''))
    
    # Fix: Salt must be padded to 32 bytes (64 hex characters)
    salt_bytes = bytes.fromhex(salt_hex.replace('0x', '').zfill(64))
    bytecode_bytes = bytes.fromhex(bytecode_hex.replace('0x', ''))

    # Calculate hash of the bytecode
    k_code = keccak.new(digest_bits=256)
    k_code.update(bytecode_bytes)
    code_hash = k_code.digest()

    # Calculate final address hash
    k_final = keccak.new(digest_bits=256)
    k_final.update(prefix + sender_bytes + salt_bytes + code_hash)
    raw_address = k_final.digest()
    
    # Return the last 20 bytes
    return raw_address[-20:].hex().lower()

# ==========================================
# 增加：Library 部署与链接逻辑
# ==========================================

def compile_contract_with_link(source_code, library_addresses=None):
    """
    支持库链接的编译函数
    :param library_addresses: 格式为 {'LibName': '0xAddress'}
    """
    compiler_params = {
        "evm_version": 'shanghai',
        "optimize": True,
        "optimize_runs": 200,
    }

    if library_addresses:
        # 核心：通知编译器将字节码中的占位符替换为真实的库地址
        compiler_params["libraries"] = library_addresses

    install_solc_versions()
    # 注意：这里需要传入所有相关的 source，或者合并 source
    compiled_sol = solcx.compile_source(
        source_code,
        output_values=['abi', 'bin'],
        **compiler_params
    )
    return compiled_sol

SETH_IP = "127.0.0.1"
SETH_PORT = 23001
PRIVATE_KEY = "c75f8d9b2a6bc0fe68eac7fef67c6b6f7c4f85163d58829b59110ff9e9210848"

def test_transfer():
    client = SethClient(SETH_IP, SETH_PORT)
    OTHER_ADDR = "1234567890abcdef1234567890abcdef12345678"

    # --- 1. Transfer ---
    print("[Task 1] Sending standard transfer...")
    tx_transfer = client.send_transaction_auto(PRIVATE_KEY, OTHER_ADDR, step=StepType.kNormalFrom, amount=1000)
    if client.wait_for_receipt(tx_transfer):
        print("✓ Transfer success.")

def test_contract():
    client = SethClient(SETH_IP, SETH_PORT)
    # --- 2. Compile Contract ---
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
    
    # --- 3. Deploy Contract (with constructor arguments) ---
    print("[Step 2] Deploying...")
    # Constructor argument encoding: 'Hello Seth!'
    constructor_args = eth_abi.encode(['string'], ["Hello Seth!"]).hex()
    deploy_code = interface['bin'] + constructor_args
    
    # Replace CONTRACT_ADDR if it is deterministically derived, 
    # otherwise, it's usually obtained from the receipt after deployment.
    # For demonstration purposes, we use your deterministic calculation function.
    TARGET_CONTRACT = calc_create2_address(client.get_address(PRIVATE_KEY), "00", deploy_code)
    
    tx_deploy = client.send_transaction_auto(PRIVATE_KEY, TARGET_CONTRACT, step=StepType.kCreateContract, contract_code=deploy_code, prepayment=10000000)
    client.wait_for_receipt(tx_deploy, timeout=30)
    print(f"✓ Contract deployed at: {TARGET_CONTRACT}")

    # --- 4. Update Data (Calling setMessage) ---
    print("[Step 3] Updating message...")
    new_text = "Updated at " + time.ctime()
    selector_set = get_selector("setMessage(string)")
    input_set = selector_set + eth_abi.encode(['string'], [new_text]).hex()
    
    tx_update = client.send_transaction_auto(PRIVATE_KEY, TARGET_CONTRACT, step=8, input_hex=input_set)
    client.wait_for_receipt(tx_update)
    print(f"✓ Message updated to: {new_text}")

    # --- 5. Query Data (Calling getMessage) ---
    print("[Step 4] Querying message...")
    selector_get = get_selector("getMessage()")
    # Note: getMessage() has no parameters, so input contains only the selector
    raw_output = client.query_contract(client.get_address(PRIVATE_KEY), TARGET_CONTRACT, selector_get)
    
    if raw_output:
        print(f"🔎 Current Message in Contract: {raw_output}")
    else:
        print("✗ Query failed.")

def test_library():
    client = SethClient(SETH_IP, SETH_PORT)
    MY_ADDR = client.get_address(PRIVATE_KEY)
    # --- 1. 定义 Library 和 主合约 ---
    lib_source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    library MathLib {
        function add(uint256 a, uint256 b) public pure returns (uint256) {
            return a + b;
        }
    }
    """

    contract_source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    import "MathLib"; // 逻辑引用

    contract Calculator {
        uint256 public lastResult;
        function doAdd(uint256 a, uint256 b) public {
            lastResult = MathLib.add(a, b);
        }
    }
    """
    
    # 将源码合并（模拟文件引用）
    full_source = lib_source + "\n" + contract_source

    # --- 2. 部署 Library ---
    print("[Task Library] Compiling and Deploying MathLib...")
    lib_compile = compile_contract(lib_source) # 简单编译库
    lib_bin = lib_compile['bin']
    
    # 计算库地址并发送部署交易 (Step 6 为部署)
    LIB_TARGET = calc_create2_address(MY_ADDR, "01", lib_bin) # 使用不同的 salt "01"
    tx_lib = client.send_transaction_auto(PRIVATE_KEY, LIB_TARGET, step=StepType.kCreateLibrary, contract_code=lib_bin, prepayment=5000000)
    client.wait_for_receipt(tx_lib)
    print(f"✓ MathLib deployed at: 0x{LIB_TARGET}")

    # --- 3. 链接并部署主合约 ---
    print("[Task Contract] Linking MathLib and Deploying Calculator...")
    
    # 格式必须符合 solc 要求：'<文件名>:<库名>': '地址'
    # 因为我们是 compile_source 且合并了源码，文件名默认为 '<stdin>'
    link_refs = {
        "<stdin>:MathLib": "0x" + LIB_TARGET
    }
    
    # 使用带链接功能的编译
    contract_compiled = compile_contract_with_link(full_source, library_addresses=link_refs)
    # 获取 Calculator 合约的编译产物
    calculator_interface = contract_compiled['<stdin>:Calculator']
    calc_bin = calculator_interface['bin']

    # 部署主合约
    CALC_TARGET = calc_create2_address(MY_ADDR, "02", calc_bin)
    tx_calc = client.send_transaction_auto(PRIVATE_KEY, CALC_TARGET, step=StepType.kCreateContract, contract_code=calc_bin, prepayment=10000000)
    client.wait_for_receipt(tx_calc)
    print(f"✓ Calculator deployed at: 0x{CALC_TARGET}")

    # --- 4. 调用主合约（间接调用 Library） ---
    print("[Task Interaction] Calling Calculator.doAdd(10, 20)...")
    selector_add = get_selector("doAdd(uint256,uint256)")
    input_add = selector_add + eth_abi.encode(['uint256', 'uint256'], [10, 20]).hex()
    
    tx_call = client.send_transaction_auto(PRIVATE_KEY, CALC_TARGET, step=8, input_hex=input_add)
    client.wait_for_receipt(tx_call)
    
    # 查询结果
    selector_res = get_selector("lastResult()")
    raw_res = client.query_contract(MY_ADDR, CALC_TARGET, selector_res)
    print(f"🔎 Calculation Result from Library: {raw_res}")

# ==========================================
# Full Lifecycle Test
# ==========================================
if __name__ == "__main__":
    # test_transfer()
    # test_contract()
    test_library()