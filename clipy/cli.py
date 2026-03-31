from seth3 import SethWeb3Mock, compile_and_link, calc_create2_address, StepType

def test_library_with_contrcat(SETH_IP, SETH_PORT, PRIV_KEY):
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

    # 1. Deploy Library
    l_bin, l_abi = compile_and_link(source, "MathLib")
    l_addr = calc_create2_address(MY_ADDR, "30", l_bin)
    tx_l = w3.client.send_transaction_auto(PRIV_KEY, l_addr, StepType.kCreateLibrary, contract_code=l_bin, prepayment=10**7)
    w3.client.wait_for_receipt(tx_l) # Use actual tx hash
    print(f"Library deployed at: {l_addr}")

    # 2. Deploy Calculator
    c_bin, c_abi = compile_and_link(source, "Calculator", libs={"MathLib": l_addr})
    c_addr = calc_create2_address(MY_ADDR, "31", c_bin)
    tx_c = w3.client.send_transaction_auto(PRIV_KEY, c_addr, StepType.kCreateContract, contract_code=c_bin, prepayment=10**7)
    w3.client.wait_for_receipt(tx_c) # Use actual tx hash
    print(f"Contract deployed at: {c_addr}")

    # 3. Web3 Interaction
    calc = w3.eth.contract(address=c_addr, abi=c_abi, sender_address=MY_ADDR)
    receipt = calc.functions.doAdd(33, 66).transact(PRIV_KEY)
    
    print(f"⭐ Decoded Result: {receipt.get('decoded_output')}")
    for e in receipt.get('decoded_events', []):
        print(f"🔔 Event: {e['event']} -> {e['args']}")

def test_transfer(SETH_IP, SETH_PORT, PRIV_KEY, RECEIVER_ADDR):
    w3 = SethWeb3Mock(SETH_IP, SETH_PORT)
    MY_ADDR = w3.client.get_address(PRIV_KEY)
    receipt_tx = w3.eth.send_transaction({
        'to': RECEIVER_ADDR,
        'value': 10000
    }, PRIV_KEY)
    
    print(f"Transfer receipt status: {receipt_tx['status']}")
    print(f"Sender Balance after: {w3.client.get_balance(MY_ADDR)}")
    print(f"Receiver Balance after: {w3.client.get_balance(RECEIVER_ADDR)}")



# --- 增加所需的 Solidity 源码变量 (如果外部未定义) ---
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
    w3 = SethWeb3Mock(SETH_IP, SETH_PORT)
    sender = w3.client.get_address(PRIV_KEY)
    
    print("\n=== Web3 Style: Bridge -> Treasury -> Pool Chain Test ===")

    # 1. Helper: 内部部署函数，保持 Web3 风格
    def web3_deploy(source, name, args_types, args_vals, salt, label, amount=0):
        # 编译
        compiled = solcx.compile_source(source, output_values=["abi", "bin"], evm_version="shanghai")
        contract_interface = compiled[f"<stdin>:{name}"]
        bytecode = contract_interface['bin']
        abi = contract_interface['abi']
        
        # 编码构造函数参数并拼接
        ctor_encoded = eth_abi.encode(args_types, args_vals).hex()
        full_bytecode = bytecode + ctor_encoded
        
        # 计算地址并部署
        target_addr = calc_create2_address(sender, salt, full_bytecode)
        print(f"[Deploying] {label} at 0x{target_addr}")
        
        tx_hash = w3.client.send_transaction_auto(
            PRIV_KEY, target_addr, step=StepType.kCreateContract, 
            contract_code=full_bytecode, prepayment=10**7
        )
        w3.client.wait_for_receipt(tx_hash)
        
        # 返回 w3 风格合约对象
        return w3.eth.contract(address=target_addr, abi=abi, sender_address=sender)

    # 2. 按顺序部署合约
    # Pool (初始注入 10000 SETH, 10000 USDC)
    pool_contract = web3_deploy(PROBE_POOL_SOL, "ProbePool", 
                                ["uint256", "uint256"], [10000, 10000], 
                                "p_salt_01", "Pool")

    # Treasury (连接到 Pool)
    treasury_contract = web3_deploy(PROBE_TREASURY_SOL, "ProbeTreasury", 
                                    ["address"], [to_checksum_address("0x" + pool_contract.address)], 
                                    "t_salt_01", "Treasury")

    # Bridge (连接到 Treasury)
    bridge_contract = web3_deploy(PROBE_BRIDGE_SOL, "ProbeBridge", 
                                  ["address"], [to_checksum_address("0x" + treasury_contract.address)], 
                                  "b_salt_01", "Bridge")

    # 3. 设置权限 (Treasury 只允许来自 Bridge 的调用)
    print("Configuring Treasury: setBridge...")
    bridge_addr_checksum = to_checksum_address("0x" + bridge_contract.address)
    treasury_contract.functions.setBridge(bridge_addr_checksum).transact(PRIV_KEY)

    # 4. 执行链式调用: Bridge.request(minOut=1) 携带 Value=5
    # 路径: User -> Bridge -> Treasury -> Pool
    print("\n[Executing] Bridge.request(1) with 5 SETH...")
    receipt = bridge_contract.functions.request(1).transact(PRIV_KEY, prepayment=10**6) 
    # 注意：如果需要携带主代币(Value)，在 send_transaction_auto 逻辑中需对应 amount
    # 这里修改 transact 内部逻辑或直接使用底层 send 以确保携带 amount=5
    
    # 重新包装一个带 Value 的 transact 调用
    tx_hash_chain = w3.client.send_transaction_auto(
        PRIV_KEY, bridge_contract.address, step=StepType.kContractExcute,
        input_hex=bridge_contract.functions.request(1).encoded_input,
        amount=5, # 携带 5 个 SETH 进入逻辑
        prepayment=10**6
    )
    final_receipt = w3.client.wait_for_receipt(tx_hash_chain, bridge_contract.abi, "request")

    # 5. 结果验证
    if final_receipt.get('status') == 0:
        print(f"✅ Chain Call Success!")
        print(f"   Decoded Output (AmountOut): {final_receipt.get('decoded_output')}")
    else:
        print(f"❌ Chain Call Failed: Status {final_receipt.get('status')}")

    # 6. 使用 call() 验证状态
    res_seth = pool_contract.functions.reserveSETH().call()
    res_usdc = pool_contract.functions.reserveUSDC().call()
    total_reqs = bridge_contract.functions.totalRequests().call()
    
    print(f"\nFinal State:")
    print(f" - Pool SETH Reserve: {res_seth}")
    print(f" - Pool USDC Reserve: {res_usdc}")
    print(f" - Bridge Total Requests: {total_reqs}")

# --- 修改 main 部分以匹配调用 ---
if __name__ == "__main__":
    SETH_IP, SETH_PORT = "127.0.0.1", 23001
    PRIV_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    
    # 执行原有测试
    test_library_with_contrcat(SETH_IP, SETH_PORT, PRIV_KEY)
    
    # 执行新增加的跨合约调用测试
    test_contract_call_contract(SETH_IP, SETH_PORT, PRIV_KEY)

if __name__ == "__main__":
    SETH_IP, SETH_PORT = "127.0.0.1", 23001
    PRIV_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    # 测试library和合约调用library
    test_library_with_contrcat(SETH_IP, SETH_PORT, PRIV_KEY)

    # 测试普通交易转账
    test_transfer(SETH_IP, SETH_PORT, PRIV_KEY, "71e571862c0e4aefa87a3c16057a62c8331991a1")

    # 测试合约调用合约
    test_contract_call_contract(SETH_IP, SETH_PORT, PRIV_KEY)