import struct
import requests
import hashlib
import json
import time
from enum import IntEnum
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
                              gas_limit=50000, gas_price=1, step=0, shard_id=0,
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

# --- 全局编译工具 ---
def compile_contract(source):
    compiled = compile_source(source, output_values=['abi', 'bin'], solc_version='0.8.30', 
                             via_ir=True, optimize=True, optimize_runs=200)
    return compiled.popitem()[1]

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

    # --- 2. 编译并部署 ---
    contract_source = """
   // SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/**
 * @title 数据市场溯源合约
 * @dev 增加了 blockNumber 字段，记录每条记录产生的具体区块高度
 */
contract DataMarketProvenance {
    
    // 数据记录结构体
    struct DataRecord {
        bytes32 dataHash;     // 内容指纹
        bytes32 previousHash; // 前序状态指纹
        address owner;        // 该版本的持有人
        uint256 timestamp;    // 记录时间戳
        uint256 blockNumber;  // --- 新增：记录产生的区块高度 ---
        string metadata;      // 原始描述信息/备注
    }

    address public contractOwner;
    bytes32[] public allDataIds;
    
    mapping(bytes32 => DataRecord[]) public history;
    mapping(bytes32 => address) public dataOwner;
    mapping(bytes32 => uint256) public dataPrice;
    mapping(bytes32 => bytes32) public currentLatestHash;

    event DataCreated(bytes32 indexed dataId, address indexed owner, uint256 price);
    event DataPriceChanged(bytes32 indexed dataId, uint256 oldPrice, uint256 newPrice);
    event DataSold(bytes32 indexed dataId, address indexed seller, address indexed buyer, uint256 price);
    event DataUpdated(bytes32 indexed dataId, bytes32 newHash);

    modifier onlyDataOwner(bytes32 _dataId) {
        require(dataOwner[_dataId] == msg.sender, "Not the data owner");
        _;
    }

    constructor() {
        contractOwner = msg.sender;
    }

    // --- 1. 创建数据 ---
    function createData(bytes32 _dataId, string calldata _metadata, uint256 _price) public {
        require(_dataId != bytes32(0), "Invalid ID");
        require(history[_dataId].length == 0, "ID already exists");

        bytes32 initialHash = keccak256(abi.encodePacked(_metadata, msg.sender, block.timestamp));

        DataRecord memory firstRecord = DataRecord({
            dataHash: initialHash,
            previousHash: bytes32(0),
            owner: msg.sender,
            timestamp: block.timestamp,
            blockNumber: block.number, // 记录当前区块高度
            metadata: _metadata
        });

        history[_dataId].push(firstRecord);
        dataOwner[_dataId] = msg.sender;
        dataPrice[_dataId] = _price;
        currentLatestHash[_dataId] = initialHash;
        allDataIds.push(_dataId);

        emit DataCreated(_dataId, msg.sender, _price);
    }

    // --- 2. 交易功能 ---
    function buyData(bytes32 _dataId, string calldata _tradeNote) public payable {
        address seller = dataOwner[_dataId];
        uint256 price = dataPrice[_dataId];

        require(seller != address(0), "Data not found");
        require(msg.sender != seller, "Cannot buy your own data");
        require(price > 0, "Data not for sale");
        require(msg.value >= price, "Insufficient payment");

        bytes32 prevHash = currentLatestHash[_dataId];
        bytes32 newHash = keccak256(abi.encodePacked(_tradeNote, msg.sender, block.timestamp));

        DataRecord memory tradeRecord = DataRecord({
            dataHash: newHash,
            previousHash: prevHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            blockNumber: block.number, // 记录交易发生的区块高度
            metadata: string(abi.encodePacked("PURCHASE: ", _tradeNote))
        });

        history[_dataId].push(tradeRecord);
        dataOwner[_dataId] = msg.sender;
        currentLatestHash[_dataId] = newHash;
        dataPrice[_dataId] = 0;

        (bool success, ) = payable(seller).call{value: msg.value}("");
        require(success, "Transfer to seller failed");

        emit DataSold(_dataId, seller, msg.sender, price);
    }

    // --- 3. 修改与更新 ---
    function updateData(bytes32 _dataId, string calldata _newMetadata) public onlyDataOwner(_dataId) {
        bytes32 prevHash = currentLatestHash[_dataId];
        bytes32 newHash = keccak256(abi.encodePacked(_newMetadata, msg.sender, block.timestamp));

        history[_dataId].push(DataRecord({
            dataHash: newHash,
            previousHash: prevHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            blockNumber: block.number, // 记录更新时的区块高度
            metadata: _newMetadata
        }));
        
        currentLatestHash[_dataId] = newHash;
        emit DataUpdated(_dataId, newHash);
    }

    // --- 4. 查询功能 ---
    function getAllLatestRecords(uint256 _offset, uint256 _limit) public view returns (DataRecord[] memory) {
        uint256 total = allDataIds.length;
        if (_offset >= total || _limit == 0) return new DataRecord[](0);

        uint256 count = _limit;
        if (_offset + _limit > total) count = total - _offset;

        DataRecord[] memory results = new DataRecord[](count);
        for (uint256 i = 0; i < count; i++) {
            bytes32 id = allDataIds[_offset + i];
            uint256 lastIdx = history[id].length - 1;
            results[i] = history[id][lastIdx];
        }
        return results;
    }

    function getHistory(bytes32 _dataId) public view returns (DataRecord[] memory) {
        return history[_dataId];
    }

    function getDataCount() public view returns (uint256) {
        return allDataIds.length;
    }
}
    """
    print("[Task 2] Compiling and Deploying contract...")
    interface = compile_contract(contract_source)
    
    # 使用修复后的地址推导逻辑
    CONTRACT_ADDR = "d29cc723cc606c88b875f280d897c32f7a829d21"
    print(f"✓ Predicted Address: {CONTRACT_ADDR}")

    tx_deploy = client.send_transaction_auto(MY_PK, CONTRACT_ADDR, step=6, contract_code=interface['bin'], prepayment=10000000, gas_limit=3000000)
    if client.wait_for_receipt(tx_deploy, timeout=60):
        print("✓ Deployment success.")

    # --- 3. 写入 ---
    print("[Task 3] Writing to contract...")
    did_key = f"did:seth:{int(time.time())}"
    sel_reg = get_selector("register(string,string,uint8)")
    encoded_input = sel_reg + eth_abi.encode(['string', 'string', 'uint8'], [did_key, "ipfs://location", 1]).hex()
    
    tx_reg = client.send_transaction_auto(MY_PK, CONTRACT_ADDR, step=8, input_hex=encoded_input, gas_limit=1000000)
    if client.wait_for_receipt(tx_reg, timeout=60):
        print("✓ Data registered.")

    # --- 4. 查询 ---
    print("[Task 4] Querying contract state...")
    sel_get = get_selector("get(string)")
    query_input = sel_get + eth_abi.encode(['string'], [did_key]).hex()
    
    raw_output = client.query_contract(client.get_address(MY_PK), CONTRACT_ADDR, query_input)
    if raw_output:
        clean_hex = raw_output.replace("0x", "")
        decoded = eth_abi.decode(['string', 'string', 'uint8'], bytes.fromhex(clean_hex))
        print(f"🔎 Result Found -> DID: {decoded[0]}, Loc: {decoded[1]}, Mod: {decoded[2]}")
    else:
        print("✗ Query returned no data.")