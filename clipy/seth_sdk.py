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

try:
    import oqs
except ImportError:
    oqs = None

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
        raw_res = self.contract.client.query_contract(
            self.contract.sender_address, self.contract.address, self.encoded_input
        )
        
        # Fallback values that won't crash .hex() or index lookups
        # Matches (uint256, uint256, bytes32, bytes32, bool)
        default_return = [0, 0, b'\x00'*32, b'\x00'*32, False]

        if not raw_res or "error" in str(raw_res).lower():
            return default_return

        try:
            if isinstance(raw_res, bytes):
                clean_bytes = raw_res
            else:
                clean_str = str(raw_res).replace('0x', '').strip()
                clean_bytes = bytes.fromhex(clean_str)

            return eth_abi.decode(self.output_types, clean_bytes)
            
        except Exception as e:
            print(f"DEBUG: Decoding failed. Raw length: {len(clean_bytes) if 'clean_bytes' in locals() else 0} bytes")
            # If it's a single return value, return 0; if it's a tuple, return our safe defaults
            return default_return if len(self.output_types) > 1 else 0

    def transact(self, private_key: str, value: int = 0, prepayment: int = 10**6, oqs_pubkey: str = None) -> dict:
        """Transaction logic with automatic parsing. Supports OQS auto-detection."""
        
        # 1. Auto-detect private key type: ECDSA hex length is 64, OQS hex length is usually > 2000
        is_oqs = len(private_key) > 128

        if is_oqs:
            # Get OQS public key: prioritize getting it from the contract object's attributes
            # If you saved oqs_pubkey when deploying or initializing SethContract, it can be used directly here
            if not oqs_pubkey:
                # Alternative: If not preset, try deriving it from global/cache based on the private key (if liboqs supports it)
                # Or throw an exception to remind the user to set the public key in the contract object
                raise ValueError(
                    "OQS detected by key length, but 'oqs_pubkey' is not set in SethContract. "
                    "Please set 'contract.oqs_pubkey = ...' before calling transact."
                )

            tx_hash = self.contract.client.send_oqs_transaction(
                private_key, 
                oqs_pubkey, 
                self.contract.address, 
                StepType.kContractExcute, 
                amount=value, 
                input_hex=self.encoded_input, 
                prepayment=prepayment
            )
        else:
            # Execute standard ECDSA logic
            tx_hash = self.contract.client.send_transaction_auto(
                private_key, 
                self.contract.address, 
                StepType.kContractExcute, 
                amount=value, 
                input_hex=self.encoded_input, 
                prepayment=prepayment
            )

        # 2. Wait for and return the receipt
        return self.contract.client.wait_for_receipt(
            tx_hash, 
            abi=self.contract.abi, 
            function_name=self.name
        )

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
        """Web3-style deployment. Automatically detects OQS based on private_key length."""
        # 1. Extract base parameters
        sender = transaction.get('from', self.sender_address)
        salt = str(transaction.get('salt', '0'))
        step = transaction.get('step', StepType.kCreateContract)
        amount = transaction.get('amount', 0)
        args = transaction.get('args', [])

        # 2. Process bytecode and constructor arguments
        full_bytecode = self.bytecode
        if args:
            ctor = next((x for x in self.abi if x['type'] == 'constructor'), None)
            if ctor:
                full_bytecode += eth_abi.encode([i['type'] for i in ctor['inputs']], args).hex()

        # 3. Calculate deployment address
        self.address = calc_create2_address(sender, salt, full_bytecode)

        # 4. Automatically select transaction interface based on private key length
        # ECDSA private key hex length is 64, OQS (e.g., Dilithium) private key hex length is usually > 2000
        if len(private_key) > 128:
            # Compatibility handling: attempt to get pubkey from the transaction dictionary
            oqs_pubkey = transaction.get('pubkey')
            if not oqs_pubkey:
                raise ValueError("OQS deployment requires 'pubkey' inside the transaction dict.")
                
            tx_hash = self.client.send_oqs_transaction(
                private_key, 
                oqs_pubkey, 
                self.address, 
                step, 
                contract_code=full_bytecode, 
                prepayment=10000000, 
                amount=amount
            )
        else:
            tx_hash = self.client.send_transaction_auto(
                private_key, 
                self.address, 
                step, 
                contract_code=full_bytecode, 
                prepayment=10000000, 
                amount=amount
            )

        # 5. Wait for and return the result
        self.client.wait_for_receipt(tx_hash)
        return self

class SethWeb3Mock:
    def __init__(self, host: str, port: int):
        self.client = SethClient(host, port)
        self.seth = self

    def contract(self, address: str = None, abi: list = None, bytecode: str = None, sender_address: str = ""):
        return SethContract(self.client, address, abi, bytecode, sender_address)
    
    def send_transaction(self, tx_dict: dict, private_key: str) -> dict:
        tx_hash = self.client.send_transaction_auto(private_key, tx_dict['to'], StepType.kNormalFrom, amount=tx_dict.get('value', 0))
        return self.client.wait_for_receipt(tx_hash)
    
    def send_oqs_transaction(self, tx_dict: dict, private_key: str) -> dict:
        """Fix: Send Post-Quantum (OQS) transaction"""
        # Must get the OQS public key from tx_dict, as OQS signature requires it
        pubkey = tx_dict.get('pubkey')
        if not pubkey:
            raise ValueError("OQS transaction requires 'pubkey' in tx_dict")
            
        # Call the method specifically handling OQS in the client
        tx_hash = self.client.send_oqs_transaction(
            private_key,     # The private_key here should be the OQS private key
            pubkey,          # OQS public key
            tx_dict['to'], 
            StepType.kNormalFrom, 
            amount=tx_dict.get('value', 0)
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
        self.oqs_url = f"http://{host}:{port}/oqs_transaction"

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
        """Polls for the transaction receipt and automatically calls decode_receipt once retrieved."""
        while True:
            resp = requests.post(self.receipt_url, data={"tx_hash": tx_hash}).json()
            print(resp)
            
            # Status codes 10001 (Pending) or 10003 (Accepted) indicate processing is still in progress
            if resp.get("status") not in [10001, 10003]:
                # Receipt found! Decode if ABI and function name are provided
                if abi and function_name:
                    return self.decode_receipt(resp, abi, function_name)
                return resp
                
            time.sleep(5)  # Poll once every 5 seconds

    def decode_receipt(self, receipt: dict, abi: list, function_name: str = None) -> dict:
        status = receipt.get("status")
        raw_out_b64 = receipt.get("output", "")
        raw_events = receipt.get("events", [])
        
        receipt['decoded_output'] = None
        receipt['decoded_events'] = []

        # --- 1. Parse Return Value (Output) ---
        if status == 0 and raw_out_b64 and function_name and abi:
            try:
                raw_bytes = base64.b64decode(raw_out_b64)
                item = next((i for i in abi if i.get('name') == function_name), None)
                if item and 'outputs' in item:
                    decoded = eth_abi.decode([o['type'] for o in item['outputs']], raw_bytes)
                    receipt['decoded_output'] = decoded[0] if len(decoded) == 1 else decoded
            except: 
                pass

        # --- 2. Parse Events ---
        if abi and raw_events:
            # First, build a mapping table for topic0 -> event_abi
            event_map = {}
            for item in [i for i in abi if i.get('type') == 'event']:
                sig = f"{item['name']}({','.join([i['type'] for i in item['inputs']])})"
                # Calculate topic0: keccak256("EventName(type1,type2)")
                topic0 = keccak.new(digest_bits=256).update(sig.encode()).digest().hex()
                event_map[topic0] = item

            for e in raw_events:
                try:
                    # Seth's topics are a list of Base64 encoded strings
                    t0_hex = base64.b64decode(e['topics'][0]).hex()
                    
                    if t0_hex in event_map:
                        spec = event_map[t0_hex]
                        data_bytes = base64.b64decode(e['data'])
                        
                        # Distinguish between indexed and non-indexed parameters
                        # Note: In Seth's simplified implementation, all data might be packed in 'data',
                        # or partially in 'topics'. This assumes standard EVM logic: non-indexed are in 'data'.
                        types = [i['type'] for i in spec['inputs'] if not i.get('indexed')]
                        names = [i['name'] for i in spec['inputs'] if not i.get('indexed')]
                        
                        vals = eth_abi.decode(types, data_bytes)
                        receipt['decoded_events'].append({
                            "event": spec['name'],
                            "args": dict(zip(names, vals))
                        })
                except Exception as ex:
                    print(f"Event decode error: {ex}")

        return receipt
    
    def get_oqs_address(self, pubkey_hex: str) -> str:
        """
        Fix: Synchronize server-side C++ logic
        str_addr_ = common::Hash::keccak256(str_pk_).substr(0, 20)
        """
        pub_bytes = bytes.fromhex(pubkey_hex.replace('0x', ''))
        # Must use Keccak256
        k = keccak.new(digest_bits=256)
        k.update(pub_bytes)
        return k.digest()[:20].hex()
    
    def send_oqs_transaction(self, oqs_sk_hex, oqs_pk_hex, to, step, amount=0, contract_code='', input_hex='', prepayment=0):
        """发送后量子交易 - 完美适配 0.15.0/0.14.0 混合环境"""
        if not oqs:
            raise ImportError("liboqs-python is required")
            
        my_addr = self.get_oqs_address(oqs_pk_hex)
        nonce_addr = to + my_addr if step == StepType.kContractExcute else my_addr
        
        # 1. 获取 Nonce
        try:
            r = requests.post(self.query_url, data={"address": nonce_addr}).json()
            nonce = int(r.get("nonce", 0)) + 1
        except: nonce = 1

        # 2. 构造消息哈希 (Keccak256)
        msg = bytearray()
        msg.extend(struct.pack('<Q', nonce))
        msg.extend(bytes.fromhex(oqs_pk_hex.replace('0x','')))
        msg.extend(bytes.fromhex(to.replace('0x','')))
        msg.extend(struct.pack('<Q', amount))
        msg.extend(struct.pack('<Q', 5000000)) # gas_limit
        msg.extend(struct.pack('<Q', 1))       # gas_price
        msg.extend(struct.pack('<Q', int(step)))
        if contract_code: msg.extend(bytes.fromhex(contract_code))
        if input_hex: msg.extend(bytes.fromhex(input_hex))
        if prepayment > 0: msg.extend(struct.pack('<Q', prepayment))

        txh = keccak.new(digest_bits=256).update(msg).digest()

        # 3. 执行 ML-DSA-44 (Dilithium2) 签名
        with oqs.Signature('ML-DSA-44') as signer:
            import ctypes
            
            # A. 消息哈希：直接用原生的 bytes (让 oqs.py 内部去处理 create_string_buffer)
            txh_bytes = bytes(txh)
            
            # B. 私钥准备 (2560 字节)
            sk_bytes = bytes.fromhex(oqs_sk_hex.replace('0x', ''))
            sk_len = 2560 
            sk_bytes = sk_bytes.ljust(sk_len, b'\x00')[:sk_len]
            
            # C. 注入私钥并防止 free() 崩溃
            # 我们必须把私钥放进一个名为 secret_key 的 ctypes 实例中，
            # 因为 __exit__ 里的 free() 会对这个属性调用 byref()
            sk_ctypes = (ctypes.c_uint8 * sk_len).from_buffer_copy(sk_bytes)
            
            try:
                # 尝试覆盖。如果 secret_key 是 property，这可能会失败
                signer.secret_key = sk_ctypes 
            except:
                # 如果上面失败，说明它是只读的，我们要么改内部变量，要么强制注入
                # 在 0.14.0 中，内部缓冲区通常就在这里
                if hasattr(signer, '_secret_key'):
                    ctypes.memmove(signer._secret_key, sk_ctypes, sk_len)
                else:
                    # 最后的绝招：直接把对象属性替换掉
                    signer.__dict__['secret_key'] = sk_ctypes

            # D. 执行签名
            # 传 1 个参数符合 "2 positional arguments" (self + msg)
            # 且不手动构造 ctypes 避免内部 create_string_buffer 报错
            signature = signer.sign(txh_bytes)

        # 4. 转换回 Hex
        sig_hex = bytes(signature).hex()

        # 4. 组装请求
        data = {
            "nonce": str(nonce),
            "pubkey": oqs_pk_hex.replace('0x',''),
            "to": to.replace('0x',''),
            "amount": str(amount),
            "gas_limit": "5000000",
            "gas_price": "1",
            "shard_id": "0",
            "type": str(int(step)),
            "sign": sig_hex 
        }
        
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment: data["pepay"] = str(prepayment)
        
        requests.post(self.oqs_url, data=data)
        print(f"tx hash {txh.hex()}")
        return txh.hex()

    def query_contract(self, f, a, i):
        return requests.post(self.query_contract_url, data={"from": f, "address": a, "input": i}).text
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
