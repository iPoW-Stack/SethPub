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
    EVMC_REVERT = 2                 # Execution terminated by REVERT opcode (Gas may remain, output provided)
    EVMC_OUT_OF_GAS = 3             # Execution ran out of gas
    EVMC_INVALID_INSTRUCTION = 4    # Hit an INVALID instruction (0xfe as per EIP-141)
    EVMC_UNDEFINED_INSTRUCTION = 5  # Encountered an undefined instruction
    EVMC_STACK_OVERFLOW = 6         # EVM stack limit exceeded (>1024 items)
    EVMC_STACK_UNDERFLOW = 7        # Opcode required more items than available on stack
    EVMC_BAD_JUMP_DESTINATION = 8   # Violated jump destination restrictions (JUMPDEST)
    EVMC_INVALID_MEMORY_ACCESS = 9  # Tried to read/write outside memory bounds
    EVMC_CALL_DEPTH_EXCEEDED = 10   # Call depth exceeded the limit (typically 1024)
    EVMC_STATIC_MODE_VIOLATION = 11 # Restricted operation attempted in static mode
    EVMC_PRECOMPILE_FAILURE = 12    # Failure in precompiled or system contract
    EVMC_CONTRACT_VALIDATION_FAILURE = 13 # Contract validation failed (EVM 1.5/ewasm rules)
    EVMC_ARGUMENT_OUT_OF_RANGE = 14 # Argument value outside of accepted range
    EVMC_WASM_UNREACHABLE_INSTRUCTION = 15 # WASM unreachable instruction hit
    EVMC_WASM_TRAP = 16             # WASM trap hit (e.g., division by zero)
    EVMC_INSUFFICIENT_BALANCE = 17  # Caller lacks funds for value transfer

    # --- Internal Errors & Rejections (Negative Values) ---
    EVMC_INTERNAL_ERROR = -1        # Generic internal EVM implementation error
    EVMC_REJECTED = -2              # Message/code rejected by the EVM implementation
    EVMC_OUT_OF_MEMORY = -3         # Failed to allocate memory needed for execution

# --- 2. Utilities ---

def calc_create2_address(sender_hex: str, salt_hex: str, bytecode_hex: str) -> str:
    """Computes the Ethereum-style CREATE2 address."""
    sender_bytes = bytes.fromhex(sender_hex.replace('0x', '').lower())
    salt_bytes = bytes.fromhex(salt_hex.replace('0x', '').lower().zfill(64))
    bytecode_bytes = bytes.fromhex(bytecode_hex.replace('0x', '').lower())
    
    # keccak256(bytecode)
    code_hash = keccak.new(digest_bits=256).update(bytecode_bytes).digest()
    
    # keccak256(0xff + sender + salt + code_hash)
    input_data = bytes.fromhex("ff") + sender_bytes + salt_bytes + code_hash
    final_hash = keccak.new(digest_bits=256).update(input_data).digest()
    return final_hash[-20:].hex().lower()

def compile_and_link(source: str, name: str, libs: Dict[str, str] = None):
    """Compiles Solidity and replaces Library linking placeholders."""
    try:
        solcx.get_executable(version="0.8.30")
    except solcx.exceptions.SolcNotInstalled:
        print("Installing solc v0.8.30...")
        solcx.install_solc("0.8.30")
    
    solcx.set_solc_version("0.8.30")
    
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
            # Solidity linking placeholder format: __$hash$__
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
        decoded = eth_abi.decode(self.output_types, bytes.fromhex(raw_hex.replace('0x', '')))
        return decoded[0] if len(decoded) == 1 else decoded

    def transact(self, private_key: str, prepayment: int = 10**6) -> dict:
        """Sends transaction, waits for receipt, and decodes Base64 data."""
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
                    setattr(self.functions, item['name'], lambda i=item: lambda *a: SethMethod(self, i)(*a))

class SethWeb3Mock:
    def __init__(self, host: str, port: int):
        self.client = SethClient(host, port)
        self.eth = self

    def contract(self, address: str = None, abi: list = None, bytecode: str = None, sender_address: str = ""):
        return SethContract(self.client, address, abi, bytecode, sender_address)

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

    def send_transaction_auto(self, private_key_hex, to_hex, step, contract_code='', input_hex='', prepayment=0):
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex.replace('0x','')), curve=SECP256k1)
        pubkey_hex = sk.verifying_key.to_string("uncompressed").hex()
        my_addr = self.get_address(private_key_hex)
        
        # Step 8 uses a composite nonce address (to+from)
        nonce_addr = to_hex + my_addr if step == StepType.kContractExcute else my_addr
        nonce = self.get_nonce(nonce_addr) + 1

        msg = bytearray()
        msg.extend(struct.pack('<Q', nonce))
        msg.extend(bytes.fromhex(pubkey_hex))
        msg.extend(bytes.fromhex(to_hex.replace('0x','')))
        msg.extend(struct.pack('<Q', 0)) # amount
        msg.extend(struct.pack('<Q', 5000000)) # gas_limit
        msg.extend(struct.pack('<Q', 1)) # gas_price
        msg.extend(struct.pack('<Q', int(step)))
        if contract_code: msg.extend(bytes.fromhex(contract_code))
        if input_hex: msg.extend(bytes.fromhex(input_hex))
        if prepayment > 0: msg.extend(struct.pack('<Q', prepayment))
        
        tx_hash = keccak.new(digest_bits=256).update(msg).digest()
        signature = sk.sign_digest_deterministic(tx_hash, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)

        data = {
            "nonce": str(nonce), "pubkey": pubkey_hex, "to": to_hex, "amount": "0",
            "gas_limit": "5000000", "gas_price": "1", "shard_id": "0",
            "type": str(int(step)), "sign_r": signature[:32].hex(), "sign_s": signature[32:64].hex(), "sign_v": "0"
        }
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment > 0: data["pepay"] = str(prepayment)

        requests.post(self.tx_url, data=data)
        return tx_hash.hex()

    def wait_for_receipt(self, tx_hash: str, abi: list = None, function_name: str = None) -> dict:
        """Polls for receipt and automatically decodes Base64 output and events."""
        while True:
            resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}).json()
            if resp.get("status") not in [10001, 10003]:
                return self.decode_receipt(resp, abi, function_name) if abi else resp
            time.sleep(1)

    def decode_receipt(self, receipt: dict, abi: list, function_name: str = None) -> dict:
        """Converts Base64 receipt data into native Python types."""
        # Parse Return Value
        raw_out_b64 = receipt.get("output")
        if raw_out_b64 and function_name:
            item = next((i for i in abi if i.get('name') == function_name), None)
            if item and 'outputs' in item:
                raw_bytes = base64.b64decode(raw_out_b64)
                decoded = eth_abi.decode([o['type'] for o in item['outputs']], raw_bytes)
                receipt['decoded_output'] = decoded[0] if len(decoded) == 1 else decoded

        # Parse Events
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

# --- 5. Main Execution ---

if __name__ == "__main__":
    SETH_IP, SETH_PORT = "127.0.0.1", 23001
    PRIV_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    
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

    # Deploy Workflow
    l_bin, l_abi = compile_and_link(source, "MathLib")
    l_addr = calc_create2_address(MY_ADDR, "20", l_bin)
    w3.client.send_transaction_auto(PRIV_KEY, l_addr, StepType.kCreateLibrary, contract_code=l_bin, prepayment=10**7)
    w3.client.wait_for_receipt(hashlib.sha256(b"dummy").hexdigest()) # Polling simplified

    c_bin, c_abi = compile_and_link(source, "Calculator", libs={"MathLib": l_addr})
    c_addr = calc_create2_address(MY_ADDR, "21", c_bin)
    w3.client.send_transaction_auto(PRIV_KEY, c_addr, StepType.kCreateContract, contract_code=c_bin, prepayment=10**7)
    w3.client.wait_for_receipt(hashlib.sha256(b"dummy2").hexdigest())

    # Web3 Interaction
    calc = w3.eth.contract(address=c_addr, abi=c_abi, sender_address=MY_ADDR)
    receipt = calc.functions.doAdd(33, 66).transact(PRIV_KEY)
    
    print(f"⭐ Decoded Result: {receipt.get('decoded_output')}")
    for e in receipt.get('decoded_events', []):
        print(f"🔔 Event: {e['event']} -> {e['args']}")