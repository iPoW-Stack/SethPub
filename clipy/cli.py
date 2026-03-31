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

class StepType(IntEnum): # Transaction Step Type
    kNormalFrom = 0                 # User direct transfer (sender)
    kNormalTo = 1                   # Cross-shard confirmation transaction (confirmation after sender's statistics)
    kConsensusRootElectShard = 2    # Shard/Root network election transaction
    kConsensusRootTimeBlock = 3     # Time block creation transaction
    kConsensusCreateGenesisAcount = 4 # Genesis account creation transaction
    kConsensusLocalTos = 5          # Cross-shard confirmation transaction (confirmation after receiver's accumulation)
    kCreateContract = 6             # Contract deployment/creation transaction
    kContractGasPrepayment = 7      # Set contract call prepayment Gas
    kContractExcute = 8             # Execute contract call
    kRootCreateAddress = 9          # Root network create new address
    kStatistic = 12                 # Statistical transaction
    kJoinElect = 13                 # New node participates in election transaction
    kCreateLibrary = 14             # Create public contract library (Library)
    kCross = 15                     # Cross-shard anti-loss block replenishment transaction
    kRootCross = 16                 # Root network cross-shard anti-loss block replenishment transaction
    kPoolStatisticTag = 17          # Current round transaction pool statistics end tag block

class MessageHandleStatus(IntEnum): # Message Handling Status
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
    kNotExists = 100010

    # Generic execution failure
    EVMC_FAILURE = 1

    # Execution terminated by REVERT opcode
    # In this case, the remaining Gas MAY be non-zero, and additional output data MAY be provided
    EVMC_REVERT = 2

    # The execution has run out of gas
    EVMC_OUT_OF_GAS = 3

    # The designated INVALID instruction has been hit (0xfe as defined in EIP-141)
    EVMC_INVALID_INSTRUCTION = 4

    # An undefined instruction has been encountered
    EVMC_UNDEFINED_INSTRUCTION = 5

    # The execution has attempted to put more items on the EVM stack than the specified limit (1024)
    EVMC_STACK_OVERFLOW = 6

    # Execution of an opcode has required more items on the EVM stack than available
    EVMC_STACK_UNDERFLOW = 7

    # Execution has violated the jump destination restrictions (JUMPDEST)
    EVMC_BAD_JUMP_DESTINATION = 8

    # Tried to read outside memory bounds (e.g., RETURNDATACOPY reading past available buffer)
    EVMC_INVALID_MEMORY_ACCESS = 9

    # Call depth has exceeded the limit (typically 1024)
    EVMC_CALL_DEPTH_EXCEEDED = 10

    # Tried to execute an operation that is restricted in static mode (state modification during STATICCALL)
    EVMC_STATIC_MODE_VIOLATION = 11

    # A call to a precompiled or system contract has ended with a failure
    EVMC_PRECOMPILE_FAILURE = 12

    # Contract validation has failed (e.g., due to EVM 1.5 jump validity, ewasm rules, etc.)
    EVMC_CONTRACT_VALIDATION_FAILURE = 13

    # An argument to a state accessing method has a value outside of the accepted range
    EVMC_ARGUMENT_OUT_OF_RANGE = 14

    # A WebAssembly `unreachable` instruction has been hit during execution
    EVMC_WASM_UNREACHABLE_INSTRUCTION = 15

    # A WebAssembly trap has been hit (e.g., division by zero, validation errors, etc.)
    EVMC_WASM_TRAP = 16

    # The caller does not have enough funds for value transfer
    EVMC_INSUFFICIENT_BALANCE = 17

    # --- Internal errors and rejections (negative values) ---

    # EVM implementation generic internal error
    EVMC_INTERNAL_ERROR = -1

    # The execution of the given code and/or message has been rejected by the EVM implementation
    EVMC_REJECTED = -2

    # The VM failed to allocate the amount of memory needed for execution
    EVMC_OUT_OF_MEMORY = -3
    
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

    def wait_for_receipt(self, tx_hash, timeout=60):
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}, timeout=2)
                if resp.status_code == 200:
                    status = resp.json().get("status")
                    msg = resp.json().get("msg")
                    print(f"Transaction {tx_hash} receipt status: {status}, output: {msg}")
                    if status not in [MessageHandleStatus.kMessageHandle, MessageHandleStatus.kTxAccept]:
                        print(resp.json())
                        return resp.json()
            except: pass
            time.sleep(5)
        return None

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

def compile_contract_with_link(source_code, library_addresses=None):
    """
    :param library_addresses: {'MathLib': '0x...'}
    """
    lib_str = None
    if library_addresses:
        lib_parts = []
        for lib_name, addr in library_addresses.items():
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

SETH_IP = "127.0.0.1" # IP updated based on logs
SETH_PORT = 23001
PRIVATE_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"

def test_library():
    client = SethClient(SETH_IP, SETH_PORT)
    MY_ADDR = client.get_address(PRIVATE_KEY)
    
    # --- 1. Source Code Definition (import statements removed) ---
    full_source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    library MathLib { 
        function add(uint256 a, uint256 b) public pure returns (uint256) { return a+b; } 
        function dec(uint256 a, uint256 b) public pure returns (uint256) { return a-b; } 
    }

    contract Calculator {
        uint256 public lastResult;
        // Added returns (uint256)
        function doAdd(uint256 a, uint256 b) public returns (uint256) {
            lastResult = MathLib.add(a, b);
            return lastResult; // Return the result
        }

        function doDec(uint256 a, uint256 b) public returns (uint256) {
            lastResult = MathLib.dec(a, b);
            return lastResult; // Return the result
        }
    }
    """

    # --- 2. Deploy Library ---
    print("[Task Library] Compiling and Deploying MathLib...")
    # Extract separate library code for compilation
    lib_source = """
    pragma solidity ^0.8.0;
    library MathLib { 
        function add(uint256 a, uint256 b) public pure returns (uint256) { return a+b; } 
        function dec(uint256 a, uint256 b) public pure returns (uint256) { return a-b; } 
    }
    """
    lib_compile = compile_contract(lib_source) # Assuming compile_contract is defined elsewhere or meant to be compile_solidity_contract
    lib_bin = lib_compile['bin'] # Assuming the output structure is {'<stdin>:MathLib': {'bin': '...', 'abi': [...]}}
    
    LIB_TARGET = calc_create2_address(MY_ADDR, "02", lib_bin)
    # Use step=14 (kCreateLibrary) to deploy public library and add prepayment
    tx_lib = client.send_transaction_auto(PRIVATE_KEY, LIB_TARGET, step=StepType.kCreateLibrary, contract_code=lib_bin, prepayment=10000000)
    
    res_json = client.wait_for_receipt(tx_lib)
    if res_json["status"] == MessageHandleStatus.kConsensusSuccess:
        print(f"✓ MathLib deployed at: 0x{LIB_TARGET}")
    else:
        print("✗ MathLib deployment failed, but proceeding to link...")

    # --- 3. Link and Deploy Main Contract ---
    print("[Task Contract] Linking MathLib and Deploying Calculator...")
    link_refs = {"MathLib": LIB_TARGET}
    
    # Compile main contract string
    contract_compiled = compile_contract_with_link(full_source, library_addresses=link_refs)
    calculator_interface = contract_compiled['<stdin>:Calculator']
    calc_bin = calculator_interface['bin']

    CALC_TARGET = calc_create2_address(MY_ADDR, "03", calc_bin)
    tx_calc = client.send_transaction_auto(PRIVATE_KEY, CALC_TARGET, step=StepType.kCreateContract, contract_code=calc_bin, prepayment=10000000)
    res_json = client.wait_for_receipt(tx_calc) # Wait for the Calculator deployment transaction
    if res_json and res_json["status"] == MessageHandleStatus.kConsensusSuccess:
        print(f"✓ Calculator deployed at: 0x{CALC_TARGET}")

        # --- 4. Call Test ---
        print("[Task Interaction] Calling Calculator.doAdd(10, 20)...")
        input_add = get_selector("doAdd(uint256,uint256)") + eth_abi.encode(['uint256', 'uint256'], [10, 20]).hex() # Encode function call
        tx_call = client.send_transaction_auto(PRIVATE_KEY, CALC_TARGET, step=StepType.kContractExcute, input_hex=input_add) # Send transaction to execute contract
        res_json_call = client.wait_for_receipt(tx_call) # Wait for the contract call transaction
        if res_json_call and res_json_call["status"] == MessageHandleStatus.kConsensusSuccess:
            raw_res = client.query_contract(MY_ADDR, CALC_TARGET, get_selector("lastResult()")) # Query the contract state
            print(f"🔎 Result: {raw_res}")
        else:
            print("✗ Contract call failed.")
    else:
        print("✗ Calculator deployment failed.")

if __name__ == "__main__":
    test_library()