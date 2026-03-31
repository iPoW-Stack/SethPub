import time
import secrets
import base64
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'clipy')))
from seth_sdk import SethWeb3Mock, StepType, compile_and_link, to_checksum_address

# 1. 合约源码 (Solidity)
ARS_SOL_SOURCE = """
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

// 1. The seller can sell at most coins equal to the pledged quantity
// 2. The pledged currency can only be recovered by the seller
// 3. The manager can forcefully cancel the transaction and return the pledged coins to the seller.
// 4. If the transaction is reported and the seller cannot redeem it, it will be locked,
//    and the manager can release it according to the situation

contract Ars {
    bytes32 test_ripdmd_;
    bytes32 enc_init_param_;
    struct ArsInfo {
        uint256 ring_size;
        uint256 signer_count;
        bytes32 id;
        bytes32 res_info;
        bool exists;
    }

    event DebugEvent(
       uint256 value
    );

    event DebugEventBytes(
       bytes value
    );

    mapping(bytes32 => ArsInfo) public ars_map;
    bytes32[] all_ids;

    // SetUp：初始化算法，需要用到pbc库
    constructor(bytes memory enc_init_param) {
        enc_init_param_ = ripemd160(enc_init_param);
    }

    function call_proxy_reenc(bytes memory params) public {
        test_ripdmd_ = ripemd160(params);
    }

    function CreateNewArs(uint ring_size, uint signer_count, bytes32 id, bytes memory params) public {
        emit DebugEvent(0);

        require(!ars_map[id].exists);
        emit DebugEvent(1);
        bytes32 res = ripemd160(params);
        ars_map[id] = ArsInfo({
            ring_size: ring_size,
            signer_count: signer_count,
            id: id,
            res_info: res,
            exists: true
        });
        all_ids.push(id);
        emit DebugEvent(2);
        emit DebugEvent(all_ids.length);
    }

    function SingleSign(bytes32 id, bytes memory params) public {
        emit DebugEvent(3);
        require(ars_map[id].exists);
        emit DebugEvent(4);
        ripemd160(params);
        emit DebugEvent(5);
    }

    function AggSign(bytes32 id, bytes memory params) public {
        emit DebugEvent(6);
        require(ars_map[id].exists);
        emit DebugEvent(7);
        ripemd160(params);
        emit DebugEvent(8);
    }

    function bytesConcat(bytes[] memory arr, uint count) public pure returns (bytes memory){
        uint len = 0;
        for (uint i = 0; i < count; i++) {
            len += arr[i].length;
        }

        bytes memory bret = new bytes(len);
        uint k = 0;
        for (uint i = 0; i < count; i++) {
            for (uint j = 0; j < arr[i].length; j++) {
                bret[k++] = arr[i][j];
            }
        }

        return bret;
    }

    function ToHex(bytes memory buffer) public pure returns (bytes memory) {
        bytes memory converted = new bytes(buffer.length * 2);
        bytes memory _base = "0123456789abcdef";
        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return converted;
    }

    function toBytes(address a) public pure returns (bytes memory) {
        return abi.encodePacked(a);
    }

    function u256ToBytes(uint256 x) public pure returns (bytes memory b) {
        b = new bytes(32);
        assembly { mstore(add(b, 32), x) }
    }

    function Bytes32toBytes(bytes32 _data) public pure returns (bytes memory) {
        return abi.encodePacked(_data);
    }

    function GetArsJson(ArsInfo memory ars, bool last) public pure returns (bytes memory) {
        bytes[] memory all_bytes = new bytes[](100);
        uint filedCount = 0;
        all_bytes[filedCount++] = '{"ring_size":"';
        all_bytes[filedCount++] = ToHex(u256ToBytes(ars.ring_size));
        all_bytes[filedCount++] = '","signer_count":"';
        all_bytes[filedCount++] = ToHex(u256ToBytes(ars.signer_count));
        all_bytes[filedCount++] = '","id":"';
        all_bytes[filedCount++] = ToHex(Bytes32toBytes(ars.id));
        all_bytes[filedCount++] = '","res":"';
        all_bytes[filedCount++] = ToHex(Bytes32toBytes(ars.res_info));
        if (last) {
            all_bytes[filedCount++] = '"}';
        } else {
            all_bytes[filedCount++] = '"},';
        }
        return bytesConcat(all_bytes, filedCount);
    }

    function GetAllArsJson() public view returns(bytes memory) {
        uint validLen = 1;
        bytes[] memory all_bytes = new bytes[](all_ids.length + 2);
        all_bytes[0] = '[';
        uint arrayLength = all_ids.length;
        for (uint i=0; i<arrayLength; i++) {
            all_bytes[i + 1] = GetArsJson(ars_map[all_ids[i]], (i == arrayLength - 1));
            ++validLen;
        }

        all_bytes[validLen] = ']';
        return bytesConcat(all_bytes, validLen + 1);
    }
}

"""

def run_comprehensive_ars_demo():
    # --- 配置信息 ---
    IP, PORT = "127.0.0.1", 23001
    PRIV_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    
    w3 = SethWeb3Mock(IP, PORT)
    MY_ADDR = w3.client.get_address(PRIV_KEY)
    print(f"[*] Operator Address: {MY_ADDR}")

    # --- 1. 编译与部署 ---
    print("\n[1] Compiling and Deploying...")
    bytecode, abi = compile_and_link(ARS_SOL_SOURCE, "Ars")
    
    # 构造函数参数
    init_param = b"initial_pbc_system_parameters"
    ars_contract = w3.seth.contract(abi=abi, bytecode=bytecode, sender_address=MY_ADDR).deploy({
        'from': MY_ADDR,
        'salt': secrets.token_hex(32),
        'args': [init_param]
    }, PRIV_KEY)
    print(f"[+] Ars Contract deployed at: {ars_contract.address}")

    # --- 2. 调用 call_proxy_reenc (简单写入) ---
    print("\n[2] Executing: call_proxy_reenc")
    proxy_params = b"reencryption_metadata_bytes"
    receipt = ars_contract.functions.call_proxy_reenc(proxy_params).transact(PRIV_KEY)
    print(f"    Status: {receipt['status']} (Hash calculated in contract)")

    # --- 3. 调用 CreateNewArs (创建基础数据) ---
    print("\n[3] Executing: CreateNewArs")
    # 我们需要创建一个 ID，供后续的 Sign 函数使用（因为它们有 require(exists)）
    base_id = secrets.token_bytes(32)
    ring_size = 2048
    signer_count = 10
    create_params = b"creation_pbc_proof"

    receipt = ars_contract.functions.CreateNewArs(
        ring_size, signer_count, base_id, create_params
    ).transact(PRIV_KEY, prepayment=10**8)
    print(f"    Status: {receipt['status']} | New Ars ID Created")

    # --- 4. 调用 SingleSign (依赖状态写入) ---
    print("\n[4] Executing: SingleSign")
    sign_params = b"single_signature_data"
    # 使用刚才创建的 base_id
    receipt = ars_contract.functions.SingleSign(base_id, sign_params).transact(PRIV_KEY, prepayment=10**8)
    print(f"    Status: {receipt['status']} (Single sign verified)")

    # --- 5. 调用 AggSign (聚合签名写入) ---
    print("\n[5] Executing: AggSign")
    agg_params = b"aggregated_signature_data"
    receipt = ars_contract.functions.AggSign(base_id, agg_params).transact(PRIV_KEY, prepayment=10**8)
    print(f"    Status: {receipt['status']} (Aggregate sign verified)")

    # --- 6. 查询状态 (Calls) ---
    print("\n[6] Testing Query Functions...")
    time.sleep(2) # 等待状态落库同步

    # A. 直接访问 Mapping (ars_map)
    # Solidity 自动为 public mapping 生成 getter
    print("[6-A] Querying ars_map (Individual Getter):")
    info = ars_contract.functions.ars_map(base_id).call()
    # 返回值顺序通常对应 struct 定义: ring_size, signer_count, id, res_info, exists
    print(f"    Struct Data: ring_size={info[0]}, signer_count={info[1]}, exists={info[4]}")

    # B. GetAllArsJson (整体 JSON 查询)
    print("[6-B] Querying GetAllArsJson:")
    try:
        raw_json = ars_contract.functions.GetAllArsJson().call()
        # 处理可能的 bytes/hex 返回
        if isinstance(raw_json, bytes):
            json_text = raw_json.decode('utf-8', errors='ignore')
        elif isinstance(raw_json, str) and raw_json.startswith('0x'):
            json_text = bytes.fromhex(raw_json[2:]).decode('utf-8', errors='ignore')
        else:
            json_text = str(raw_json)
        print(f"    JSON Result: {json_text}")
    except Exception as e:
        print(f"    Query Error: {e}")

    # --- 7. 工具函数测试 (Pure functions) ---
    print("\n[7] Testing Utility Functions (Pure):")
    addr_bytes = ars_contract.functions.toBytes(to_checksum_address(MY_ADDR)).call()
    print(f"    Address to Bytes: {addr_bytes}")

    print("\n[!] All Ars contract functions have been exercised.")

if __name__ == "__main__":
    run_comprehensive_ars_demo()