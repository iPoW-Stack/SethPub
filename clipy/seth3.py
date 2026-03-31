from __future__ import annotations
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
    kCross = 15                     # Cross-shard anti-loss block replenishment
    kRootCross = 16                 # Root network cross-shard replenishment
    kPoolStatisticTag = 17          # End tag for transaction pool statistics round

class MessageHandleStatus(IntEnum):
    """Status codes for message handling and EVM execution."""
    kConsensusSuccess = 0
    kMessageHandle = 10001
    kMessageHandleError = 10002
    kTxAccept = 10003
    kTxInvalidSignature = 10004
    kTxInvalidAddress = 10005
    kTxPoolFullReject = 10006
    kTxUserNonceInvalid = 10007
    kUnkonwn = 10008
    kRequestInvalid = 10009
    kNotExists = 10010

    # --- EVMC Standard Runtime Status ---
    EVMC_SUCCESS = 0                # Execution finished with success
    EVMC_FAILURE = 1                # Generic execution failure
    EVMC_REVERT = 2                 # Execution terminated by REVERT opcode
    EVMC_OUT_OF_GAS = 3             # Execution ran out of gas
    EVMC_INVALID_INSTRUCTION = 4    # Hit an INVALID instruction
    EVMC_UNDEFINED_INSTRUCTION = 5  # Encountered an undefined instruction
    EVMC_STACK_OVERFLOW = 6         # EVM stack limit exceeded
    EVMC_STACK_UNDERFLOW = 7        # Opcode required more items than available
    EVMC_BAD_JUMP_DESTINATION = 8   # Violated jump destination restrictions
    EVMC_INVALID_MEMORY_ACCESS = 9  # Tried to read/write outside memory bounds
    EVMC_CALL_DEPTH_EXCEEDED = 10   # Call depth exceeded the limit
    EVMC_STATIC_MODE_VIOLATION = 11 # Restricted operation attempted in static mode
    EVMC_PRECOMPILE_FAILURE = 12    # Failure in precompiled or system contract
    EVMC_CONTRACT_VALIDATION_FAILURE = 13 # Contract validation failed
    EVMC_ARGUMENT_OUT_OF_RANGE = 14 # Argument value outside of accepted range
    EVMC_WASM_UNREACHABLE_INSTRUCTION = 15 # WASM unreachable instruction hit
    EVMC_WASM_TRAP = 16             # WASM trap hit
    EVMC_INSUFFICIENT_BALANCE = 17  # Caller lacks funds for value transfer

    # --- Internal Errors & Rejections ---
    EVMC_INTERNAL_ERROR = -1        # Generic internal EVM implementation error
    EVMC_REJECTED = -2              # Message/code rejected by the EVM
    EVMC_OUT_OF_MEMORY = -3         # Failed to allocate memory

# --- 2. Utilities ---

def calc_create2_address(sender_hex: str, salt_hex: str, bytecode_hex: str) -> str:
    """Computes the Ethereum-style CREATE2 address."""
    sender_bytes = bytes.fromhex(sender_hex.replace('0x', '').lower())
    salt_bytes = bytes.fromhex(salt_hex.replace('0x', '').lower().zfill(64))
    bytecode_bytes = bytes.fromhex(bytecode_hex.replace('0x', '').lower())
    
    code_hash = keccak.new(digest_bits=256).update(bytecode_bytes).digest()
    input_data = bytes.fromhex("ff") + sender_bytes + salt_bytes + code_hash
    final_hash = keccak.new(digest_bits=256).update(input_data).digest()
    return final_hash[-20:].hex().lower()

def compile_and_link(source: str, name: str, libs: Dict[str, str] = None):
    """Compiles Solidity and replaces Library linking placeholders."""
    try:
        solcx.install_solc("0.8.30")
        solcx.set_solc_version("0.8.30")
    except Exception as e:
        print(f"Solc installation/set issue: {e}")

    compiled = solcx.compile_source(
        source, 
        output_values=['bin', 'abi'], 
        optimize=True, 
        evm_version='shanghai'
    )
    
    data = compiled[f"<stdin>:{name}"]
    bytecode = data['bin']
    
    if libs:
        for lib, addr in libs.items():
            placeholder = keccak.new(digest_bits=256).update(f"<stdin>:{lib}".encode()).hexdigest()[:34]
            bytecode = bytecode.replace(f"__${placeholder}$__", addr.replace('0x','').lower())
            
    return bytecode, data['abi']

# --- 3. Web3 Mock Components ---

class SethMethod:
    def __init__(self, contract: SethContract, abi_item: dict):
        self.contract = contract
        self.abi_item = abi_item
        self.name = abi_item['name']
        self.input_types = [p['type'] for p in abi_item.get('inputs', [])]
        self.output_types = [p['type'] for p in abi_item.get('outputs', [])]

    def __call__(self, *args) -> SethMethod:
        """Encodes parameters: calculates selector + ABI encoding."""
        sig = f"{self.name}({','.join(self.input_types)})"
        selector = keccak.new(digest_bits=256).update(sig.encode()).digest()[:4].hex()
        self.encoded_input = selector + eth_abi.encode(self.input_types, args).hex()
        return self

    def call(self) -> Any:
        """Read-only call: Automatically parses hex return value."""
        raw_hex = self.contract.client.query_contract(
            self.contract.sender_address, self.contract.address, self.encoded_input
        )
        if not raw_hex or "error" in raw_hex.lower(): return None
        raw_hex = raw_hex.replace('0x', '')
        decoded = eth_abi.decode(self.output_types, bytes.fromhex(raw_hex))
        return decoded[0] if len(decoded) == 1 else decoded

    def transact(self, private_key: str, prepayment: int = 10**6) -> dict:
        """Sends transaction, waits for receipt, and decodes data."""
        tx_hash = self.contract.client.send_transaction_auto(
            private_key_hex=private_key,
            to_hex=self.contract.address,
            step=StepType.kContractExcute,
            input_hex=self.encoded_input,
            prepayment=prepayment
        )
        print(f"Transaction sent. Hash: {tx_hash}")
        return self.contract.client.wait_for_receipt(tx_hash, abi=self.contract.abi, function_name=self.name)

class SethContract:
    def __init__(self, client: SethClient, address: str, abi: list, bytecode: str, sender_address: str):
        self.client = client
        self.address = address
        self.abi = abi
        self.bytecode = bytecode
        self.sender_address = sender_address
        self.functions = type('Functions', (), {})()
        
        if abi:
            for item in abi:
                if item.get('type') == 'function':
                    setattr(self.functions, item['name'], self._create_method(item))

    def _create_method(self, item):
        return lambda *args: SethMethod(self, item)(*args)

class SethWeb3Mock:
    def __init__(self, host: str, port: int):
        self.client = SethClient(host, port)
        self.eth = self

    def contract(self, address: str = None, abi: list = None, bytecode: str = None, sender_address: str = ""):
        return SethContract(self.client, address, abi, bytecode, sender_address)
    
    def send_transaction(self, tx_dict: dict, private_key: str) -> dict:
        """Standard Transfer simulation."""
        tx_hash = self.client.send_transaction_auto(
            private_key_hex=private_key,
            to_hex=tx_dict['to'],
            amount=tx_dict.get('value', 0),
            step=StepType.kNormalFrom
        )
        return self.client.wait_for_receipt(tx_hash)

# --- 4. Base Client ---

class SethClient:
    def __init__(self, host, port):
        self.base_url = f"http://{host}:{port}"
        self.tx_url = f"{self.base_url}/transaction"
        self.query_url = f"{self.base_url}/query_account"
        self.receipt_url = f"{self.base_url}/transaction_receipt"
        self.query_contract_url = f"{self.base_url}/query_contract"

    def get_address(self, private_key_hex):
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex.replace('0x','')), curve=SECP256k1)
        pub_key = sk.verifying_key.to_string("uncompressed")[1:]
        return keccak.new(digest_bits=256).update(pub_key).digest()[-20:].hex()

    def get_balance(self, address):
        try:
            resp = requests.post(self.query_url, data={"address": address}, timeout=5)
            return int(resp.json().get("balance", 0)) if resp.status_code == 200 else 0
        except: return 0

    def send_transaction_auto(self, private_key_hex, to_hex, step, amount=0, contract_code='', input_hex='', prepayment=0):
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex.replace('0x','')), curve=SECP256k1)
        pubkey_hex = sk.verifying_key.to_string("uncompressed").hex()
        my_addr = self.get_address(private_key_hex)
        
        nonce_addr = to_hex + my_addr if step == StepType.kContractExcute else my_addr
        nonce = self.get_nonce(nonce_addr) + 1

        msg = bytearray()
        msg.extend(struct.pack('<Q', nonce))
        msg.extend(bytes.fromhex(pubkey_hex))
        msg.extend(bytes.fromhex(to_hex.replace('0x','')))
        msg.extend(struct.pack('<Q', amount)) 
        msg.extend(struct.pack('<Q', 5000000)) 
        msg.extend(struct.pack('<Q', 1)) 
        msg.extend(struct.pack('<Q', int(step)))
        if contract_code: msg.extend(bytes.fromhex(contract_code))
        if input_hex: msg.extend(bytes.fromhex(input_hex))
        if prepayment > 0: msg.extend(struct.pack('<Q', prepayment))
        
        tx_hash = keccak.new(digest_bits=256).update(msg).digest()
        signature = sk.sign_digest_deterministic(tx_hash, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)

        data = {
            "nonce": str(nonce), "pubkey": pubkey_hex, "to": to_hex, "amount": str(amount),
            "gas_limit": "5000000", "gas_price": "1", "shard_id": "0",
            "type": str(int(step)), "sign_r": signature[:32].hex(), "sign_s": signature[32:64].hex(), "sign_v": "0"
        }
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment > 0: data["pepay"] = str(prepayment)

        requests.post(self.tx_url, data=data)
        return tx_hash.hex()

    def wait_for_receipt(self, tx_hash: str, abi: list = None, function_name: str = None) -> dict:
        while True:
            resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}).json()
            if resp.get("status") not in [10001, 10003]:
                return self.decode_receipt(resp, abi, function_name) if abi else resp
            time.sleep(1)

    def decode_receipt(self, receipt: dict, abi: list, function_name: str = None) -> dict:
        raw_out_b64 = receipt.get("output")
        if raw_out_b64 and function_name:
            item = next((i for i in abi if i.get('name') == function_name), None)
            if item and 'outputs' in item:
                raw_bytes = base64.b64decode(raw_out_b64)
                decoded = eth_abi.decode([o['type'] for o in item['outputs']], raw_bytes)
                receipt['decoded_output'] = decoded[0] if len(decoded) == 1 else decoded

        raw_events = receipt.get("events", [])
        if raw_events and abi:
            decoded_events = []
            event_map = {}
            for item in abi:
                if item.get('type') == 'event':
                    sig = f"{item['name']}({','.join([i['type'] for i in item['inputs']])})"
                    topic0 = keccak.new(digest_bits=256).update(sig.encode()).digest().hex()
                    event_map[topic0] = item

            for event in raw_events:
                t0_hex = base64.b64decode(event['topics'][0]).hex()
                if t0_hex in event_map:
                    spec = event_map[t0_hex]
                    data_bytes = base64.b64decode(event['data'])
                    types = [i['type'] for i in spec['inputs'] if not i.get('indexed')]
                    vals = eth_abi.decode(types, data_bytes)
                    decoded_events.append({"event": spec['name'], "args": dict(zip([i['name'] for i in spec['inputs']], vals))})
            receipt['decoded_events'] = decoded_events
        return receipt

    def get_nonce(self, address):
        try: return int(requests.post(self.query_url, data={"address": address}).json().get("nonce", 0))
        except: return 0

    def query_contract(self, from_hex, to_hex, input_hex):
        return requests.post(self.query_contract_url, data={"from": from_hex, "address": to_hex, "input": input_hex}).text

# --- 5. Test Functions ---

def test_library_with_contrcat(SETH_IP, SETH_PORT, PRIV_KEY):
    print("\n--- TEST CASE 1: Library and Library-calling Contract ---")
    w3 = SethWeb3Mock(SETH_IP, SETH_PORT)
    MY_ADDR = w3.client.get_address(PRIV_KEY)

    source = """
    pragma solidity ^0.8.0;
    library MathLib { function add(uint256 a, uint256 b) public pure returns (uint256) { return a + b; } }
    contract Calculator {
        uint256 public val;
        event TestEvent(uint256 value);
        function doAdd(uint256 a, uint256 b) public returns (uint256) {
            val = MathLib.add(a, b);
            emit TestEvent(val);
            return val;
        }
    }
    """

    # --- 1. Deploy Library (Web3 Style) ---
    print("Deploying Library...")
    l_bin, l_abi = compile_and_link(source, "MathLib")
    
    # We use a mock factory pattern
    # salt "30" for Library
    lib_addr = calc_create2_address(MY_ADDR, "30", l_bin)
    w3.eth.contract(abi=l_abi, bytecode=l_bin).deploy(
        transaction={'from': MY_ADDR, 'salt': "30", 'step': StepType.kCreateLibrary},
        private_key=PRIV_KEY
    )
    print(f"Library deployed at: {lib_addr}")

    # --- 2. Deploy Calculator (Web3 Style) ---
    print("Deploying Calculator...")
    # Linking is handled in compile_and_link
    c_bin, c_abi = compile_and_link(source, "Calculator", libs={"MathLib": lib_addr})
    
    # salt "31" for Contract
    calc_addr = calc_create2_address(MY_ADDR, "31", c_bin)
    calculator = w3.eth.contract(abi=c_abi, bytecode=c_bin).deploy(
        transaction={'from': MY_ADDR, 'salt': "31", 'step': StepType.kCreateContract},
        private_key=PRIV_KEY
    )
    print(f"Contract deployed at: {calc_addr}")

    calc = w3.eth.contract(address=calc_addr, abi=c_abi, sender_address=MY_ADDR)
    receipt = calc.functions.doAdd(33, 66).transact(PRIV_KEY)
    
    print(f"⭐ Decoded Result: {receipt.get('decoded_output')}")
    for e in receipt.get('decoded_events', []):
        print(f"🔔 Event: {e['event']} -> {e['args']}")

def test_transfer(SETH_IP, SETH_PORT, PRIV_KEY, RECEIVER_ADDR):
    print("\n--- TEST CASE 2: Standard Transfer ---")
    w3 = SethWeb3Mock(SETH_IP, SETH_PORT)
    MY_ADDR = w3.client.get_address(PRIV_KEY)
    receipt_tx = w3.eth.send_transaction({
        'to': RECEIVER_ADDR,
        'value': 10000
    }, PRIV_KEY)
    
    print(f"Transfer receipt status: {receipt_tx['status']}")
    print(f"Sender Balance after: {w3.client.get_balance(MY_ADDR)}")
    print(f"Receiver Balance after: {w3.client.get_balance(RECEIVER_ADDR)}")

# Contract Sources for Test Case 3
PROBE_POOL_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ProbePool {
    uint256 public reserveSETH; uint256 public reserveUSDC;
    constructor(uint256 _reserveSETH, uint256 _reserveUSDC) payable {
        reserveSETH = _reserveSETH; reserveUSDC = _reserveUSDC;
    }
    function sellSETH(uint256 minOut) external payable returns (uint256 out) {
        out = (msg.value * reserveUSDC) / (reserveSETH + msg.value);
        require(out >= minOut, "ProbePool: slippage");
        reserveSETH += msg.value; reserveUSDC -= out;
        return out;
    }
}
"""
PROBE_TREASURY_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ProbeTreasury {
    address public pool; address public bridge; uint256 public totalSwaps;
    constructor(address _pool) payable { pool = _pool; }
    function setBridge(address _bridge) external { bridge = _bridge; }
    function swap(uint256 minOut) external payable returns (uint256 out) {
        require(msg.sender == bridge, "ProbeTreasury: not bridge");
        (bool ok, bytes memory ret) = pool.call{value: msg.value}(
            abi.encodeWithSignature("sellSETH(uint256)", minOut)
        );
        require(ok, "ProbeTreasury: pool call failed");
        out = abi.decode(ret, (uint256));
        totalSwaps += 1;
        return out;
    }
}
"""
PROBE_BRIDGE_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ProbeBridge {
    address public treasury; uint256 public totalRequests;
    constructor(address _treasury) { treasury = _treasury; }
    function request(uint256 minOut) external payable returns (uint256 out) {
        (bool ok, bytes memory ret) = treasury.call{value: msg.value}(
            abi.encodeWithSignature("swap(uint256)", minOut)
        );
        require(ok, "ProbeBridge: treasury call failed");
        out = abi.decode(ret, (uint256));
        totalRequests += 1;
        return out;
    }
}
"""

def test_contract_call_contract(SETH_IP, SETH_PORT, PRIV_KEY):
    print("\n--- TEST CASE 3: Contract Chain Call (Bridge -> Treasury -> Pool) ---")
    w3 = SethWeb3Mock(SETH_IP, SETH_PORT)
    sender = w3.client.get_address(PRIV_KEY)
    
    def web3_deploy(source, name, args_types, args_vals, salt, label):
        compiled = solcx.compile_source(source, output_values=["abi", "bin"], evm_version="shanghai")
        contract_interface = compiled[f"<stdin>:{name}"]
        bytecode = contract_interface['bin']
        abi = contract_interface['abi']
        
        ctor_encoded = eth_abi.encode(args_types, args_vals).hex()
        full_bytecode = bytecode + ctor_encoded
        
        target_addr = calc_create2_address(sender, salt, full_bytecode)
        print(f"[Deploying] {label} at 0x{target_addr}")
        
        tx_hash = w3.client.send_transaction_auto(
            PRIV_KEY, target_addr, step=StepType.kCreateContract, 
            contract_code=full_bytecode, prepayment=10**7
        )
        w3.client.wait_for_receipt(tx_hash)
        return w3.eth.contract(address=target_addr, abi=abi, sender_address=sender)

    # Deploy Chain
    pool_contract = web3_deploy(PROBE_POOL_SOL, "ProbePool", 
                                ["uint256", "uint256"], [10000, 10000], 
                                "p_salt_01", "Pool")

    treasury_contract = web3_deploy(PROBE_TREASURY_SOL, "ProbeTreasury", 
                                    ["address"], [to_checksum_address("0x" + pool_contract.address)], 
                                    "t_salt_01", "Treasury")

    bridge_contract = web3_deploy(PROBE_BRIDGE_SOL, "ProbeBridge", 
                                  ["address"], [to_checksum_address("0x" + treasury_contract.address)], 
                                  "b_salt_01", "Bridge")

    # Set Permission
    print("Configuring Treasury: setBridge...")
    bridge_addr_checksum = to_checksum_address("0x" + bridge_contract.address)
    treasury_contract.functions.setBridge(bridge_addr_checksum).transact(PRIV_KEY)

    # Execute Chain Call: Bridge.request(1) with Value=5
    print("\n[Executing] Bridge.request(1) with 5 SETH...")
    tx_hash_chain = w3.client.send_transaction_auto(
        PRIV_KEY, bridge_contract.address, step=StepType.kContractExcute,
        input_hex=bridge_contract.functions.request(1).encoded_input,
        amount=5, 
        prepayment=10**6
    )
    final_receipt = w3.client.wait_for_receipt(tx_hash_chain, bridge_contract.abi, "request")

    if final_receipt.get('status') == 0:
        print(f"✅ Chain Call Success!")
        print(f"   Decoded Output (AmountOut): {final_receipt.get('decoded_output')}")
    else:
        print(f"❌ Chain Call Failed: Status {final_receipt.get('status')}")

    # Verify State
    res_seth = pool_contract.functions.reserveSETH().call()
    res_usdc = pool_contract.functions.reserveUSDC().call()
    total_reqs = bridge_contract.functions.totalRequests().call()
    
    print(f"\nFinal State Verification:")
    print(f" - Pool SETH Reserve: {res_seth}")
    print(f" - Pool USDC Reserve: {res_usdc}")
    print(f" - Bridge Total Requests: {total_reqs}")

# --- Runner ---
if __name__ == "__main__":
    SETH_IP, SETH_PORT = "127.0.0.1", 23001
    PRIV_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    
    # 1. Test library and contract calling library
    test_library_with_contrcat(SETH_IP, SETH_PORT, PRIV_KEY)

    # 2. Test standard transfer (Receiver address truncated for demo)
    test_transfer(SETH_IP, SETH_PORT, PRIV_KEY, "71e571862c0e4aefa87a3c16057a62c8331991a1")

    # 3. Test contract calling contract
    test_contract_call_contract(SETH_IP, SETH_PORT, PRIV_KEY)