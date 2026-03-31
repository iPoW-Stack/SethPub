from __future__ import annotations
import secrets
import struct
import requests
import hashlib
import json
import time
import base64
from enum import IntEnum
from typing import Any, Optional, Union, Dict, List

# Core dependencies
import solcx
import eth_abi
from eth_utils import to_checksum_address
from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

# --- 1. Constants & Enums ---

class StepType(IntEnum):
    """Defines the specific type of transaction/operation step."""
    kNormalFrom = 0                 # Standard transfer (Sender side)
    kNormalTo = 1                   # Cross-shard confirmation (Sender-side statistics)
    kConsensusRootElectShard = 2    # Shard/Root network election
    kConsensusRootTimeBlock = 3     # Time block creation
    kConsensusCreateGenesisAcount = 4 # Genesis account creation
    kConsensusLocalTos = 5          # Cross-shard confirmation (Receiver-side accumulation)
    kCreateContract = 6             # Contract deployment/creation
    kContractGasPrepayment = 7      # Set contract call gas prepayment
    kContractExcute = 8             # Execute contract call
    kRootCreateAddress = 9          # Root network address creation
    kStatistic = 12                 # Statistical transaction
    kJoinElect = 13                 # Node election participation
    kCreateLibrary = 14             # Create public contract library (Library)

class MessageHandleStatus(IntEnum):
    """Status codes for message handling and EVM execution."""
    kConsensusSuccess = 0
    kMessageHandle = 10001
    kMessageHandleError = 10002
    kTxAccept = 10003

# --- 2. Utilities ---

def calc_create2_address(sender: str, salt: str, bytecode: str) -> str:
    sender = sender.lower().replace('0x', '')
    bytecode = bytecode.lower().replace('0x', '')
    
    # Ensure salt is hex; if it's a plain string like 'l1', encode it to hex
    salt_clean = str(salt).lower().replace('0x', '')
    try:
        salt_bytes = bytes.fromhex(salt_clean).zfill(32)
    except ValueError:
        # Fallback: if not hex, hash the string to get a valid 32-byte hex salt
        salt_bytes = keccak.new(digest_bits=256).update(str(salt).encode()).digest()
    
    code_hash = keccak.new(digest_bits=256).update(bytes.fromhex(bytecode)).digest()
    input_data = bytes.fromhex("ff") + bytes.fromhex(sender) + salt_bytes + code_hash
    return keccak.new(digest_bits=256).update(input_data).digest()[-20:].hex().lower()

def compile_and_link(source: str, name: str, libs: Dict[str, str] = None):
    """Compiles Solidity and replaces Library linking placeholders."""
    try:
        solcx.install_solc("0.8.30")
        solcx.set_solc_version("0.8.30")
    except: pass

    compiled = solcx.compile_source(source, output_values=['bin', 'abi'], optimize=True, evm_version='shanghai')
    
    # Flexible lookup to handle solc naming
    contract_data = None
    for key in compiled.keys():
        if key.endswith(f":{name}"):
            contract_data = compiled[key]
            break
            
    if not contract_data:
        raise KeyError(f"Contract '{name}' not found. Available: {list(compiled.keys())}")

    bytecode = contract_data['bin']
    if libs:
        for lib, addr in libs.items():
            placeholder = keccak.new(digest_bits=256).update(f"<stdin>:{lib}".encode()).hexdigest()[:34]
            bytecode = bytecode.replace(f"__${placeholder}$__", addr.lower().replace('0x', ''))
            
    return bytecode, contract_data['abi']

# --- 3. Web3 Mock Components ---

class SethMethod:
    def __init__(self, contract: SethContract, abi_item: dict):
        self.contract = contract
        self.name = abi_item['name']
        self.input_types = [p['type'] for p in abi_item.get('inputs', [])]
        self.output_types = [p['type'] for p in abi_item.get('outputs', [])]

    def __call__(self, *args) -> SethMethod:
        sig = f"{self.name}({','.join(self.input_types)})"
        selector = keccak.new(digest_bits=256).update(sig.encode()).digest()[:4].hex()
        self.encoded_input = selector + eth_abi.encode(self.input_types, args).hex()
        return self

    def call(self) -> Any:
        """Read-only call: Validates hex before decoding."""
        raw_res = self.contract.client.query_contract(
            self.contract.sender_address, self.contract.address, self.encoded_input
        )
        
        # Defensive check: if the node returns an error string like "get address failed..."
        if not raw_res or "error" in raw_res.lower() or "failed" in raw_res.lower():
            print(f"DEBUG: Query failed for {self.name}. Node returned: '{raw_res}'")
            return 0 # Or a sensible default
        
        try:
            clean_hex = raw_res.replace('0x', '').strip()
            decoded = eth_abi.decode(self.output_types, bytes.fromhex(clean_hex))
            return decoded[0] if len(decoded) == 1 else decoded
        except Exception as e:
            print(f"DEBUG: Decoding failed for {self.name}. Raw: {raw_res} | Error: {e}")
            return 0

    def transact(self, private_key: str, value: int = 0, prepayment: int = 10**6) -> dict:
        """Transaction logic with automatic parsing."""
        tx_hash = self.contract.client.send_transaction_auto(
            private_key, self.contract.address, StepType.kContractExcute, 
            amount=value, input_hex=self.encoded_input, prepayment=prepayment
        )
        return self.contract.client.wait_for_receipt(tx_hash, abi=self.contract.abi, function_name=self.name)

class SethContract:
    def __init__(self, client: SethClient, address: Optional[str], abi: list, bytecode: str = None, sender_address: str = ""):
        self.client, self.address, self.abi, self.bytecode, self.sender_address = client, address, abi, bytecode, sender_address
        self.functions = type('Functions', (), {})()
        if abi:
            for item in [i for i in abi if i.get('type') == 'function']:
                setattr(self.functions, item['name'], self._create_method(item))

    def _create_method(self, item):
        return lambda *args: SethMethod(self, item)(*args)

    def deploy(self, transaction: dict, private_key: str) -> SethContract:
        """Web3-style deployment."""
        sender = transaction.get('from', self.sender_address)
        salt = str(transaction.get('salt', '0'))
        step = transaction.get('step', StepType.kCreateContract)
        amount = transaction.get('amount', 0)
        args = transaction.get('args', [])

        full_bytecode = self.bytecode
        if args:
            ctor = next((x for x in self.abi if x['type'] == 'constructor'), None)
            if ctor:
                full_bytecode += eth_abi.encode([i['type'] for i in ctor['inputs']], args).hex()

        self.address = calc_create2_address(sender, salt, full_bytecode)
        tx_hash = self.client.send_transaction_auto(private_key, self.address, step, contract_code=full_bytecode, prepayment=10000000, amount=amount)
        self.client.wait_for_receipt(tx_hash)
        return self

class SethWeb3Mock:
    def __init__(self, host: str, port: int):
        self.client = SethClient(host, port)
        self.eth = self

    def contract(self, address: str = None, abi: list = None, bytecode: str = None, sender_address: str = ""):
        return SethContract(self.client, address, abi, bytecode, sender_address)
    
    def send_transaction(self, tx_dict: dict, private_key: str) -> dict:
        tx_hash = self.client.send_transaction_auto(private_key, tx_dict['to'], StepType.kNormalFrom, amount=tx_dict.get('value', 0))
        return self.client.wait_for_receipt(tx_hash)

# --- 4. Base Client ---

class SethClient:
    def __init__(self, host, port):
        self.base_url = f"http://{host}:{port}"
        self.tx_url = f"{self.base_url}/transaction"
        self.query_url = f"{self.base_url}/query_account"
        self.receipt_url = f"{self.base_url}/transaction_receipt"
        self.query_contract_url = f"{self.base_url}/query_contract"

    def get_address(self, pk_hex):
        sk = SigningKey.from_string(bytes.fromhex(pk_hex.replace('0x', '')), curve=SECP256k1)
        pub = sk.verifying_key.to_string("uncompressed")[1:]
        return keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()

    def send_transaction_auto(self, pk_hex, to, step, amount=0, contract_code='', input_hex='', prepayment=0):
        my_addr = self.get_address(pk_hex)
        nonce_addr = to + my_addr if step == StepType.kContractExcute else my_addr
        try:
            r = requests.post(self.query_url, data={"address": nonce_addr}).json()
            nonce = int(r.get("nonce", 0)) + 1
        except: nonce = 1

        sk = SigningKey.from_string(bytes.fromhex(pk_hex.replace('0x', '')), curve=SECP256k1)
        pub = sk.verifying_key.to_string("uncompressed").hex()

        msg = bytearray()
        msg.extend(struct.pack('<Q', nonce))
        msg.extend(bytes.fromhex(pub))
        msg.extend(bytes.fromhex(to.replace('0x','')))
        msg.extend(struct.pack('<Q', amount))
        msg.extend(struct.pack('<Q', 5000000))
        msg.extend(struct.pack('<Q', 1))
        msg.extend(struct.pack('<Q', int(step)))
        if contract_code: msg.extend(bytes.fromhex(contract_code))
        if input_hex: msg.extend(bytes.fromhex(input_hex))
        if prepayment > 0: msg.extend(struct.pack('<Q', prepayment))

        txh = keccak.new(digest_bits=256).update(msg).digest()
        sig = sk.sign_digest_deterministic(txh, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)
        
        data = {"nonce": str(nonce), "pubkey": pub, "to": to, "amount": str(amount), "gas_limit": "5000000", "gas_price": "1", "shard_id": "0", "type": str(int(step)), "sign_r": sig[:32].hex(), "sign_s": sig[32:64].hex(), "sign_v": "0"}
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment: data["pepay"] = str(prepayment)
        
        requests.post(self.tx_url, data=data)
        return txh.hex()

    def wait_for_receipt(self, tx_hash: str, abi: list = None, function_name: str = None) -> dict:
        """循环轮询回执，并在获取后自动调用 decode_receipt"""
        while True:
            resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}).json()
            print(resp)
            # 状态码 10001 (Pending) 或 10003 (Accepted) 表示还在处理中
            if resp.get("status") not in [10001, 10003]:
                # 找到回执了！如果传入了 ABI，就进行解码
                if abi and function_name:
                    return self.decode_receipt(resp, abi, function_name)
                return resp
                
            time.sleep(5) # 每秒轮询一次

    def decode_receipt(self, receipt: dict, abi: list, function_name: str = None) -> dict:
        """
        完整的回执解码函数：支持正常返回值解析与 Revert 原因解析。
        """
        status = receipt.get("status")
        raw_out_b64 = receipt.get("output", "")
        
        # 初始化解码结果字段
        receipt['decoded_output'] = None
        receipt['error_reason'] = None

        if not raw_out_b64:
            return receipt

        try:
            # 1. 统一进行 Base64 解码
            raw_bytes = base64.b64decode(raw_out_b64)
        except Exception as e:
            print(f"Base64 decode failed: {e}")
            return receipt

        # --- 情况 A: 处理合约报错 (Revert/Fail) ---
        if status != 0:
            try:
                # 检查是否为标准错误签名 Error(string) -> 0x08c379a0
                if raw_bytes.startswith(b'\x08\xc3y\xa0'):
                    # 去掉前 4 字节的 selector，解码剩下的 string
                    reason = eth_abi.decode(['string'], raw_bytes[4:])[0]
                    receipt['error_reason'] = reason
                    print(f"❌ Contract Reverted! Status: {status}, Reason: {reason}")
                else:
                    # 可能是 Panic(uint256) 或自定义错误，记录原始十六进制
                    receipt['error_reason'] = f"0x{raw_bytes.hex()}"
                    print(f"❌ Contract Failed! Status: {status}, Raw Hex: 0x{raw_bytes.hex()}")
            except Exception as e:
                print(f"Failed to decode error message: {e}")
            return receipt

        # --- 情况 B: 处理正常返回 (Success) ---
        if function_name and abi:
            try:
                # 从 ABI 查找函数定义
                item = next((i for i in abi if i.get('name') == function_name and i.get('type') == 'function'), None)
                
                if item and 'outputs' in item and len(item['outputs']) > 0:
                    output_types = [o['type'] for o in item['outputs']]
                    
                    # 执行 ABI 解码
                    decoded = eth_abi.decode(output_types, raw_bytes)
                    
                    # 如果只有一个返回值，直接取值；否则返回元组/列表
                    receipt['decoded_output'] = decoded[0] if len(decoded) == 1 else decoded
                    print(f"✅ Decoded Success: {function_name} -> {receipt['decoded_output']}")
                else:
                    # 函数没有返回值 (void)
                    receipt['decoded_output'] = None
            except Exception as e:
                print(f"ABI decoding failed for {function_name}: {e}")
                # 如果解码失败（比如长度不匹配），记录原始数据防止得出巨型数字
                receipt['decoded_output'] = f"Decode Error: 0x{raw_bytes.hex()}"

        return receipt

    def query_contract(self, f, a, i): return requests.post(self.query_contract_url, data={"from": f, "address": a, "input": i}).text
    def get_balance(self, a):
        try:
            response = requests.post(self.query_url, data={"address": a}, timeout=5)
            # Check if the response is actually JSON
            return int(response.json().get("balance", 0))
        except Exception as e:
            print(f"DEBUG: Balance query failed for {a}. Response text: '{response.text}'")
            return 0

    def get_nonce(self, a):
        try:
            response = requests.post(self.query_url, data={"address": a}, timeout=5)
            return int(response.json().get("nonce", 0))
        except Exception as e:
            print(f"DEBUG: Nonce query failed for {a}. Response text: '{response.text}'")
            return 0

# --- 5. Main Execution ---
PROBE_POOL_SOL = """
pragma solidity ^0.8.20;

contract ProbePool {
    uint256 public reserveSETH;
    uint256 public reserveUSDC;

    // 记录兑换明细：投入、产出、以及更新后的储备
    event PoolSwap(address indexed sender, uint256 amountIn, uint256 amountOut, uint256 resSETH, uint256 resUSDC);

    constructor(uint256 s, uint256 u) payable {
        reserveSETH = s;
        reserveUSDC = u;
    }

    function sellSETH(uint256 m) external payable returns (uint256 out) {
        out = (msg.value * reserveUSDC) / (reserveSETH + msg.value);
        require(out >= m, 'ProbePool: slippage');
        
        reserveSETH += msg.value;
        reserveUSDC -= out;

        emit PoolSwap(msg.sender, msg.value, out, reserveSETH, reserveUSDC);
        return out;
    }
}
"""

PROBE_TREASURY_SOL = """
pragma solidity ^0.8.20;

contract ProbeTreasury {
    address public pool;
    address public bridge;
    uint256 public totalSwaps;

    // 记录金库转发情况
    event TreasuryForwarded(address indexed poolAddr, uint256 value, uint256 minOut);

    constructor(address p) payable {
        pool = p;
    }

    function setBridge(address b) external {
        bridge = b;
    }

    function swap(uint256 m) external payable returns (uint256 out) {
        require(msg.sender == bridge, 'ProbeTreasury: not bridge');
        
        emit TreasuryForwarded(pool, msg.value, m);

        (bool ok, bytes memory ret) = pool.call{value: msg.value}(
            abi.encodeWithSignature('sellSETH(uint256)', m)
        );
        require(ok, 'ProbeTreasury: call sellSETH failed');
        
        out = abi.decode(ret, (uint256));
        totalSwaps += 1;
        return out;
    }
}
"""

PROBE_BRIDGE_SOL = """
pragma solidity ^0.8.20;

contract ProbeBridge {
    address public treasury;
    uint256 public totalRequests;

    // 记录用户发起的请求
    event BridgeRequest(address indexed user, uint256 value, uint256 minOut, uint256 requestId);

    constructor(address t) {
        treasury = t;
    }

    function request(uint256 m) external payable returns (uint256 out) {
        totalRequests += 1;
        emit BridgeRequest(msg.sender, msg.value, m, totalRequests);

        (bool ok, bytes memory ret) = treasury.call{value: msg.value}(
            abi.encodeWithSignature('swap(uint256)', m)
        );
        require(ok, 'ProbeBridge: call swap failed');
        
        out = abi.decode(ret, (uint256));
        return out;
    }
}
"""

RANDOM_SALT = secrets.token_hex(31)
def test_library_with_contrcat(w3, MY, KEY):
    print("\n--- TEST CASE 1: Library ---")
    src = "pragma solidity ^0.8.0; library MathLib { function add(uint a, uint b) public pure returns(uint){return a+b;} } contract Calculator { function use(uint a, uint b) public pure returns(uint){return MathLib.add(a,b);} }"
    l_bin, l_abi = compile_and_link(src, "MathLib")
    lib = w3.eth.contract(abi=l_abi, bytecode=l_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '01', 'step': StepType.kCreateLibrary}, KEY)
    c_bin, c_abi = compile_and_link(src, "Calculator", libs={"MathLib": lib.address})
    calc = w3.eth.contract(abi=c_abi, bytecode=c_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '02'}, KEY)
    print(f"Result: {calc.functions.use(10, 20).transact(KEY)['decoded_output']}")

def test_contract_call_contract(w3, MY, KEY):
    print("\n--- TEST CASE 3: Chain Call ---")
    p_bin, p_abi = compile_and_link(PROBE_POOL_SOL, "ProbePool")
    pool = w3.eth.contract(abi=p_abi, bytecode=p_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '03', 'args': [10000, 10000], 'amount': 5000000 }, KEY)
    
    t_bin, t_abi = compile_and_link(PROBE_TREASURY_SOL, "ProbeTreasury")
    treasury = w3.eth.contract(abi=t_abi, bytecode=t_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '04', 'args': [to_checksum_address(pool.address)], 'amount': 5000000 }, KEY)
    
    b_bin, b_abi = compile_and_link(PROBE_BRIDGE_SOL, "ProbeBridge")
    bridge = w3.eth.contract(abi=b_abi, bytecode=b_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '05', 'args': [to_checksum_address(treasury.address)]}, KEY)

    treasury.functions.setBridge(to_checksum_address(bridge.address)).transact(KEY)
    receipt = bridge.functions.request(1).transact(KEY, value=5)
    print(f"Chain Call Result (AmountOut): {receipt.get('decoded_output')}")
    print(f"Bridge Total Requests: {bridge.functions.totalRequests().call()}")

def test_transfer(w3, MY, KEY):
    print("\n--- TEST CASE 2: Standard Transfer ---")
    dest = "0000000000000000000000000000000000000001"
    print(f"Balance before: {w3.client.get_balance(dest)}")
    receipt = w3.eth.send_transaction({'to': dest, 'value': 5000}, KEY)
    print(f"Transfer Status: {receipt['status']} | Balance after: {w3.client.get_balance(dest)}")

if __name__ == "__main__":
    IP, PORT, KEY = "127.0.0.1", 23001, "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    w3 = SethWeb3Mock(IP, PORT)
    MY = w3.client.get_address(KEY)

    test_contract_call_contract(w3, MY, KEY)
    test_transfer(w3, MY, KEY)
    test_library_with_contrcat(w3, MY, KEY)