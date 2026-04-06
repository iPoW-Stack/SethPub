from __future__ import annotations
import secrets
import time
from eth_utils import to_checksum_address
import requests

from seth_sdk import SethWeb3Mock, StepType, compile_and_link

# --- 5. Main Execution ---
PROBE_POOL_SOL = """
pragma solidity ^0.8.20;

contract ProbePool {
    uint256 public reserveSETH;
    uint256 public reserveUSDC;

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
    lib = w3.seth.contract(abi=l_abi, bytecode=l_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '01', 'step': StepType.kCreateLibrary}, KEY)
    c_bin, c_abi = compile_and_link(src, "Calculator", libs={"MathLib": lib.address})
    calc = w3.seth.contract(abi=c_abi, bytecode=c_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '02'}, KEY)
    print(f"Result: {calc.functions.use(10, 20).transact(KEY)['decoded_output']}")

def test_contract_call_contract(w3, MY, KEY):
    print("\n--- TEST CASE 3: Chain Call ---")
    p_bin, p_abi = compile_and_link(PROBE_POOL_SOL, "ProbePool")
    pool = w3.seth.contract(abi=p_abi, bytecode=p_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '03', 'args': [10000, 10000], 'amount': 5000000 }, KEY)

    t_bin, t_abi = compile_and_link(PROBE_TREASURY_SOL, "ProbeTreasury")
    treasury = w3.seth.contract(abi=t_abi, bytecode=t_bin).deploy({'from': MY, 'salt': RANDOM_SALT + '04', 'args': [to_checksum_address(pool.address)], 'amount': 5000000 }, KEY)

    b_bin, b_abi = compile_and_link(PROBE_BRIDGE_SOL, "ProbeBridge")
    bridge = w3.seth.contract(abi=b_abi, bytecode=b_bin, sender_address=MY).deploy({'from': MY, 'salt': RANDOM_SALT + '05', 'args': [to_checksum_address(treasury.address)]}, KEY)

    treasury.functions.setBridge(to_checksum_address(bridge.address)).transact(KEY)
    receipt = bridge.functions.request(1).transact(KEY, value=5)
    print(f"Chain Call Result (AmountOut): {receipt.get('decoded_output')}")
    if receipt.get('status') == 0:
        print(f"✅ Chain Call Success! AmountOut: {receipt.get('decoded_output')}")

        for e in receipt.get('decoded_events', []):
            print(f"🔔 Event Log: {e['event']} -> {e['args']}")
    else:
        print(f"❌ Chain Call Failed: {receipt.get('msg')}")

    print(f"Bridge Total Requests: {bridge.functions.totalRequests().call()}")

def test_transfer(w3, MY, KEY):
    print("\n--- TEST CASE 2: Standard Transfer ---")
    dest = "620a1c023fdef21f3c10bf3d468de37d5ecfdc7b"
    print(f"Balance before: {w3.client.get_balance(dest)}")
    receipt = w3.seth.send_transaction({'to': dest, 'value': 500000000}, KEY)
    print(f"Transfer Status: {receipt['status']} | Balance after: {w3.client.get_balance(dest)}")

def test_prefund(w3, contract, KEY):
    my_address = w3.client.get_address(KEY)
    prefund_address = contract + my_address
    receipt = w3.seth.send_transaction({'to': contract, 'prefund': 500000000}, KEY)
    print(f"Transfer Status: {receipt['status']} | Balance after: {w3.client.get_balance(prefund_address)}")

def test_oqs_transfer(w3, OQS_MY, OQS_KEY, OQS_PK):
    """Test post-quantum transfer transaction"""
    print("\n--- TEST CASE 4: OQS Standard Transfer ---")
    dest = "0000000000000000000000000000000000000002"

    # Construct OQS transaction dictionary, must contain pubkey
    tx_dict = {
        'to': dest,
        'value': 8888,
        'pubkey': OQS_PK
    }

    print(f"OQS Sender: {OQS_MY}")
    print(f"Dest Balance before: {w3.client.get_balance(dest)}")

    # Call w3.send_oqs_transaction
    receipt = w3.seth.send_oqs_transaction(tx_dict, OQS_KEY)

    print(f"OQS Transfer Status: {receipt['status']}")
    print(f"Dest Balance after: {w3.client.get_balance(dest)}")

def test_oqs_prefund(w3, contract, OQS_MY, OQS_KEY, OQS_PK):
    """Test post-quantum transfer transaction"""
    print("\n--- TEST CASE 4: OQS Standard Transfer ---")
    # Construct OQS transaction dictionary, must contain pubkey
    tx_dict = {
        'to': contract,
        'prefund': 50000000,
        'pubkey': OQS_PK
    }

    print(f"OQS Sender: {OQS_MY}")
    prefund_address = contract + OQS_MY
    print(f"Dest Balance before: {w3.client.get_balance(prefund_address)}")

    # Call w3.send_oqs_transaction
    receipt = w3.seth.send_oqs_transaction(tx_dict, OQS_KEY)

    print(f"OQS Transfer Status: {receipt['status']}")
    print(f"Dest Balance after: {w3.client.get_balance(prefund_address)}")

def test_oqs_contract_deploy_and_call(w3, OQS_MY, OQS_KEY, OQS_PK):
    """Test deploying and calling a contract using a post-quantum account"""
    print("\n--- TEST CASE 5: OQS Contract Deploy & Call ---")

    src = """
    pragma solidity ^0.8.0;
    contract OqsVault {
        uint256 public data;
        event DataStored(uint256 newValue);
        function store(uint256 v) public {
            data = v;
            emit DataStored(v);
        }
    }
    """
    bin, abi = compile_and_link(src, "OqsVault")

    # 1. Deploy contract (OQS mode)
    # Pass pubkey in the transaction dictionary, deploy will auto-switch to OQS based on KEY length
    oqs_vault = w3.seth.contract(abi=abi, bytecode=bin, sender_address=OQS_MY)
    oqs_vault.deploy({
        'from': OQS_MY,
        'salt': RANDOM_SALT + 'a0',
        'pubkey': OQS_PK
    }, OQS_KEY)

    print(f"OQS Contract Deployed at: {oqs_vault.address}")

    # 2. Call contract (OQS mode)
    print("Sending OQS Contract Call...")
    receipt = oqs_vault.functions.store(12345).transact(OQS_KEY, oqs_pubkey=OQS_PK)

    if receipt.get('status') == 0:
        print(f"✅ OQS Call Success! New Data: {oqs_vault.functions.data().call()}")
        for e in receipt.get('decoded_events', []):
            print(f"🔔 OQS Event: {e['event']} -> {e['args']}")
    else:
        print(f"❌ OQS Call Failed: {receipt.get('msg')}")

def test_oqs_library_with_contract(w3, OQS_MY, OQS_KEY, OQS_PK):
    """
    Test deploying Library using OQS account and linking to business contract.
    Validation point: StepType.kCreateLibrary compatibility in OQS mode.
    """
    print("\n--- TEST CASE 6: OQS Library & Linking ---")

    src = """
    pragma solidity ^0.8.0;
    library OqsMath {
        function multiply(uint a, uint b) public pure returns(uint) {
            return a * b;
        }
    }
    contract OqsCalculator {
        function compute(uint a, uint b) public pure returns(uint) {
            return OqsMath.multiply(a, b);
        }
    }
    """

    # 1. Deploy OQS Library
    # Explicitly specify StepType.kCreateLibrary
    l_bin, l_abi = compile_and_link(src, "OqsMath")
    print("[*] Deploying OQS Library...")
    oqs_lib = w3.seth.contract(abi=l_abi, bytecode=l_bin).deploy({
        'from': OQS_MY,
        'salt': RANDOM_SALT + 'a1',
        'step': StepType.kCreateLibrary,
        'pubkey': OQS_PK
    }, OQS_KEY)
    print(f"OQS Library Deployed at: {oqs_lib.address}")

    # 2. Deploy OQS contract referencing this Library
    # Link address and perform two-stage deployment
    c_bin, c_abi = compile_and_link(src, "OqsCalculator", libs={"OqsMath": oqs_lib.address})
    print("[*] Deploying OQS Calculator (Linked)...")
    oqs_calc = w3.seth.contract(abi=c_abi, bytecode=c_bin).deploy({
        'from': OQS_MY,
        'salt': RANDOM_SALT + 'a2',
        'pubkey': OQS_PK
    }, OQS_KEY)

    # 3. Call test
    # Set contract object's public key for transact to auto-sign
    oqs_calc.oqs_pubkey = OQS_PK
    result = oqs_calc.functions.compute(7, 8).transact(OQS_KEY, oqs_pubkey=OQS_PK)

    print(f"OQS Library Call Result (7 * 8): {result.get('decoded_output')}")
    if result.get('decoded_output') == 56:
        print("✅ OQS Library & Linking Test Passed!")
    else:
        print(f"❌ OQS Library Test Failed: {result.get('msg')}")

def test_ecdsa_prefund_full_flow(w3, MY, KEY):
    print("\n--- TEST: ECDSA Prefund Logic (Full Flow) ---")
    
    src = "pragma solidity ^0.8.0; contract Vault { uint256 public val; function set(uint256 v) public { val = v; } }"
    bin, abi = compile_and_link(src, "Vault")
    
    contract = w3.seth.contract(abi=abi, bytecode=bin)
    contract.deploy({'from': MY, 'salt': RANDOM_SALT + 'ecdsapp'}, KEY) # Use RANDOM_SALT to ensure uniqueness
    addr = contract.address
    print(f"Contract deployed at: {addr}")

    initial = contract.get_prefund(MY)
    print(f"Initial Prefund: {initial}")

    # ---------------------------------------------------------
    # Deposit 5,000,000 units of Gas prefund
    deposit_amount = 5000000
    print(f"Action: Depositing {deposit_amount} to prefund...")
    
    # Call the prefund interface from the contract object
    receipt = contract.prefund(deposit_amount, KEY) # Use the contract object's prefund method
    
    if receipt.get('status') == 0:
        print("✅ Prefund Tx success.")
    else:
        print(f"❌ Prefund Tx failed: {receipt.get('msg')}")
        return

    # ---------------------------------------------------------
    count = 0
    while count < 30:
        time.sleep(2) # Wait for consensus to settle
        after_deposit = contract.get_prefund(MY)
        print(f"Prefund after deposit: {after_deposit}")
        
        if after_deposit == initial + deposit_amount:
            print("🚩 Verification 1: Accumulation SUCCESS!")
            break
        else:
            count += 1
            print("🚩 Verification 1: Accumulation FAILED!")

    # ---------------------------------------------------------
    print("Action: Executing contract call to consume gas...")
    # Note: When calling transact, passing prefund=0 means only consume existing prefund, do not deposit more
    call_receipt = contract.functions.set(888).transact(KEY, prefund=0)
    
    time.sleep(2)
    final_stats = contract.get_prefund(MY)
    consumed = after_deposit - final_stats
    
    print(f"Final Prefund: {final_stats}")
    print(f"Gas Consumed from Prefund: {consumed}")
    
    if consumed > 0:
        print("🚩 Verification 2: Consumption SUCCESS!")
    else:
        print("🚩 Verification 2: Consumption FAILED (Prefund not used)!")
    contract.refund(KEY)

def test_oqs_contract_prefund_flow(w3, OQS_MY, OQS_KEY, OQS_PK):
    """Verify the deposit and accumulation logic for contract prefund."""
    print("\n--- TEST: OQS Prefund Accumulation ---")
    
    src = "pragma solidity ^0.8.0; contract OqsVault { uint256 public data; function store(uint256 v) public { data = v; } }"
    bin, abi = compile_and_link(src, "OqsVault")
    
    oqs_vault = w3.seth.contract(abi=abi, bytecode=bin)
    oqs_vault.deploy({'from': OQS_MY, 'salt': RANDOM_SALT + 'pp01', 'pubkey': OQS_PK}, OQS_KEY)
    
    # Get contract address
    contract_addr = oqs_vault.address
    print(f"Target Contract: {contract_addr}")
    pre_pp = oqs_vault.get_prefund(OQS_MY)
    print(f"Step 1: Initial Prefund -> {pre_pp}")
    
    # --------------------------------------------------------- #
    # Step B: Execute Deposit (Prefund)
    # ---------------------------------------------------------
    add_amount = 5000000
    print(f"Step 2: Sending +{add_amount} prefund...")
    
    # Use the previously modified contract.prefund function
    receipt = oqs_vault.prefund(add_amount, OQS_KEY, oqs_pubkey=OQS_PK)
    
    if receipt.get('status') == 0:
        print("✅ Prefund transaction accepted.")
    else:
        print(f"❌ Prefund failed: {receipt.get('msg')}")
        return # Exit if prefund fails
    
    # --------------------------------------------------------- #
    # Step C: Check Prefund balance after deposit and verify accumulation
    # ---------------------------------------------------------
    # Wait a moment for consensus to complete
    count = 0
    while count < 30:
        time.sleep(2) 
        post_pp = oqs_vault.get_prefund(OQS_MY)
        print(f"Step 3: Final Prefund -> {post_pp}")

        if post_pp == pre_pp + add_amount:
            print(f"🎉 SUCCESS: Prefund accumulated correctly! ({pre_pp} + {add_amount} = {post_pp})")
            break
        else:
            count += 1
            print(f"⚠️ ERROR: Accumulation mismatch! Expected {pre_pp + add_amount}, got {post_pp}")

    # --------------------------------------------------------- #
    # Step D: Send a regular contract call and observe if Prefund is consumed
    # ---------------------------------------------------------
    print("Step 4: Executing contract call (should consume prefund)...")
    oqs_vault.functions.store(999).transact(OQS_KEY, oqs_pubkey=OQS_PK) # Passing 0 here means no additional deposit
    
    time.sleep(2)
    final_pp = oqs_vault.get_prefund(OQS_MY)
    print(f"Step 5: Prefund after execution -> {final_pp}")
    print(f"Gas consumed from prefund: {post_pp - final_pp}")
    oqs_vault.refund(OQS_KEY, oqs_pubkey=OQS_PK)
    
def ecdsa_sign_test():
    IP, PORT, KEY = "127.0.0.1", 23001, "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    w3 = SethWeb3Mock(IP, PORT)
    MY = w3.client.get_address(KEY)

    test_contract_call_contract(w3, MY, KEY)
    test_transfer(w3, MY, KEY)
    test_library_with_contrcat(w3, MY, KEY)
    test_ecdsa_prefund_full_flow(w3, MY, KEY)

def oqs_sign_test():
    # Base configuration
    IP, PORT = "127.0.0.1", 23001

    # OQS keys (using sample ML-DSA-44 length Hex string here, should actually read from oqs_addrs file)
    # Note: Private key length must be > 128 bits to trigger auto-switch logic in code
    OQS_KEY = "4a6393c16df04473176bae0b114389fc60f31ab9bb4a9e3fd01e99c62baea55abd3ff4ca55887f58c87ae1d24972c8177392b57e2188adbac7eb113df430cce335751f12fed204a775f64dd74391a89b2fd0a111e2bdd8331a75ea673692c8cedc118460e6dbc1c4512ab88a1322410c2c4984f6a0048477f9da69690edc1be4d8400683206461140654a4410a376d9aa88944023283a248d1468802104c0ca1289b065218822c52b88520086dc02085e30005190031db46810ca00899a240a33682c490712313806314094b36424bb66cc3268c54b25051822cd2960598b86412284943c8490009248b447223a16d1417859b10120bc80dcca48412b14d23370c8ca060d116058b26086290895c144aa2a40422b1919030868c3452a0840188a22824c48490a610421846e2104081880c643686a4428242228611110483b061da00508b108123064151b0841a346589062908496424a0410c398ecc9491418864da382611466d5188705c00864b924549c28dd2a0605144451437061c9800a324651ca8005ac28418458d92368ce192301a016623366012802021116c8232241b24498b483124022001418294304c20c320c22485da002440c04dcaa008839684dc422252844121142409850884c41182960912247013a910912671d1980d83428904251298826d8a384a881011a14842dc8864438091081188231930e014600c464c12290e0a216a64860101a9908c020058841158468953482203a940c2941020808023030e9144600a358482a0201c998943846483166201048924876552263121384582028802970161400ac146519ca84c24454a1086114a049151806c114680624646d448224b906844b624021951d2b265da96048bc69013c66c40b811c822801c9364e3185064b00c0c832501a3084044716008511b4410d3003292b6055a202481b29092346940282cdc18024808682296455b165113494c81282ac1026a94448c02142e2402910b444094048923218524b129c494240a036804260e13a60898321210806c22448dcab2411c054180a8892320704180080b494c43362221114c11154c1a496582988521324dc2b08ca1866c49304ee2c0411240290390251a822c8142525218205888245aa01000a6801a0249a0a2891a456411328a11446412074903242880b2494038440c8505408070183760c99668d9c00d00a43014282251a82da29851244021d1164811a82909b22c99a031021562e1a07098cefa3f7fbafb37beb94cc6a0c4edf99a3309b71ee6e874098c08f41c378c646a4cc06bd17cd134ce4d2b7ace034a4567e8298da64c53f07e0f000ea40df2fe1d8b8d48665edf453f2284d16cda33485bf24ab38b8675b13f505e8af05351d3171bc1a0aa9f98a96dcb8467c0b6311a05643d82fe8ca89b546068d3758bb78fdd89c2050009d0c45c57f55b712a4308f6ec9feba74eb1036baa4ca14c81bd2978c2b4125f91c93c9aef5782ec9e218647741eaa49e3acb1134013eba02c4f8b58c0bb58b46f26caef3fe2a176cbf198e9f45ae11ec0c832f9ad19f5596a5458293ed09f97593bcfbd0e5c21f4984ecc96fd23be33a1dd188062dbb5650cbe2329f5b3e3ee3db4196faf782e5cafdd6a6ff8dad6186a7ec016cd07f38109c673b929ab9875731c24f11b424c1f3633c767e57013c7a289e3409bf092c49f0bd3f1d47c19d26cb5fabeea5e674e3e8db2e28c7971385038d9bd0b10791f95c355acbe050fb6d079b14fe8353cda4d77e52f38df13f21a08ec529e692059fbdb15ac74af020636228585047362ae9a64462d2d4862d276da7015fa5233646f75c5a59df1e37187be6f76370fc6c0808f0ce32177473057047daf9cc63c41691d06d95966909a5d727a9f120d7e575495df58cffbb9ed1215319a39856ca82f8f91f1c077686059eee67270f1a852aefa34d4849b8a706971e1216186171aec7a873ef4cda507bda37d3a61e14cf5423e0eea7bfae92b4eed842e3812369b5a2c394bb308bce0ffc285a5fed51fe199f44c597ada7c68023cebdb5327b95a20c3512b736d651c96c14a8fd32486981908934c0c728bd8992131ec9fa521316eca9bd140c3a6a211e03e813d2090865775174dd27154f5fb335949197a32b3f4b2282daf4f86e0dd9a92a4d6c01c62a52d98cea2e3a71601b1bbe6f44de2b408137e87eba94e084dc480af489ac602002cfe3c3010ddfdb06d42b92ceedcf5562ad72fdbf9fbe9720049a7dc7565251b75c6cd3c9671d65724d571fcb59096ccde707b269dccc05a4052562cab4a3d6310fbb2d3f6edabd11c31cf2e54a462cb4c162b6e3ae1f0162c1bfab06b2feb0899b6ef8d99386fa28ac8739473cd7fcae0e4bb5714388d5a0fedb7b967c5924f03ac1019245099b54e6e4c591df81ea11354018e3348689a87f21536e4415321330d1840e71c03777415ba47209079ca22e61eafe8f1886c97f52db5e21976422ce13ba0b16fbe1e041ae4be26b41dfde8d11766e5e91e1becbca4d89e743c67d92a5202333e083e7270874df349ae5c0d5971ff30311f195adc2f2ce90bb39ae56e68e0f8bcdf48047f16f629d65138ee24683a62d05c83275bb825367ab83e4bd7dc7ef3d5824e9c95ac4c0bd0f8d11fcc054b1ef08a33899d5c97d305dd31c0225cfcccd03d7ad5f6656aa5cda4c387040d22b62d6b8b8a43e53869fd4110d37c6bb14f96c9e191b5be281ca36b423a22f64fbaa6a46ccca7aecefb16abed8dfd621cf87afbf43f3dff96961887e0df30852ece9d9c2b9848d681df2bf1cd0516e2df3a91263513f87a9b8390705086c934309390ae1df684a8db293dce305a532533b31e3b2d21dc1e8ad2886bac5b2781304f467e95bf1202447942ac6d2190d04ee34ca1de2085d4cfcff0ad13749a5b213887445680958ec6f97c2d979810f41a42e39ea6f5c14c83bb3188926343ec9d18716f8a191afe60124719879f9d14878e87a2834ce15160dcbd1ee212028ccbd0352115d793ec83fff383fa4f95a7b01250343a05d966a501d2b17a50f7dd406853f5c64fbb7d64911253de2cdfbf5303e314273a4aef97db3372eb5473f7bc8a3295ee484798e75ac7070c207bb0a238472a190262811c55768a626e83887d69eec4422b26d415604cfe2d0491771b307c04f662d2959faf3fd8250ee045899c31bd43d08abcd676708af64d7dbdd82a675d3b5eb60eac7f88404e23b4049a6c9a509c012d690658ae5bf54d88863afa6c12645878763b0546ca0472a3b206ee37b087eded75321a70671cfe3a4dc8f4b74d334ecb7c54385023657c1461eb9e3f5ac53d8d523ea88859ad1ee9853392637d47ba87dfd4c91c5707a04f3ac27d3cbd117303ec2baf269529d8a097a47d9432239646f92cd02b6c5a6532477e08cda33261dafa883613e2cb332ee5ce982ab5fe90afe2d3707237200aa1a9e32552fc606294320f7d4fa463ea8456620998d8826f26dfb70f42ca9e1a6fef224a6e42119661853d9d6b5edf57cc36aa9f1961d1662b9238e54d3cc8ea003c0717587f649f1823d4847b9b777727dec99df993d8d6fc12101dd572807ee7"
    OQS_PK = "4a6393c16df04473176bae0b114389fc60f31ab9bb4a9e3fd01e99c62baea55aee04da4794a48502fbd77be9cc3848b8b54c60bc77af76678a60f35f5d3c4eec83bb547843034dc5c62c2d46205b0c57803a868ba0992ef6941b0d848aedf97ae24cc8ad89a329c5825862280e6be2d74fefe4c3ea7561f9849042a0b50de7b914653fbefaa6273eab93236871313d6aa55ad2754be72b59d58c25ffca65b8bb5ffd807eaa59d1e6ca202fb4ba837f87439f0ce45757d56665deb7a9f133c1200d199bdfff711696cf692ec15e03f14b778a10adf26fb912cf5742e6fe633d6a45455634b6cc3fba4e14da2909c39575f59070cf9b66e5a65c799460969387dadb2fe8fb90837e36f9c68c25639f6931f19cad5870a9386a2b5081d92ddd641f42fd811f0b4b9ee8041ff08b44fd94d020ba36715400f66c515cf9ae942dab814de9c4c66e302901beb38d49c19ccadde1c6e8c16bc8472d9620171f5f8206374ffcd7df86c3ef2e22cb45e74efdc2dba52ea2f71ad41cd17b3c333429872ba112aa586b6a378923a4de3608fa0f44eb29b0a2ea08f61bd322bfa44408b8f7dc3bd57c987a8f78f59d0b5a356dd0ce66d2c7508f78f42231141712411a96f1200bfdc46cbef99f849526bd05a1e2954747b617a4517323bc7a7bd9e56590ce841b6dcb234c904219d3b85a3a8f753957b6aef37264fe49c4c188ec132d37acad296bfe99ec33ab52fef9537b7738ff13cb37d8bd21c3cd6ecb65c607cc232c11b8cfece2532965de4c133f1d7d36beb5ad3dc5d13463983e2a2668a68bd437ec857d6c4fc6c3c09417280c88a348ebb9e11ed4a20e231dc57fcdbc8cabb401dd5f1b9fa5a7da5c19ca4c3b29b3b2362d397c58d14bd71ac7d36f72d820659417e728535561293332713fd7cb7652c7ae74a3790ae9c4d4d46b32f232c84d36df5b70591c001f221cdb5af6cfd63a4e165a7d5f0cf2d8abd5165538ffc20a5d407f2a77791237d319d1e98230f5002a86d8462c4f6bccac66b43b771c01da95fd8ea4c5bc87c90cb5160e06ef68dd046e25e6ae96eb119594ee946a0bdc2510beb85f273697c907fdb029c582cdc65b9c2d8d7c44cfa4992d725bbe981101ecb092cdf3eedd67972e6936c7ba56e354313a22dee82eaed207d39e862ca349c8fdc26cbdc560da9919e965a8ae2daa67a2e95023ca94543c5cde3a9d330bb862434dfd42e9286b210b9a00786b89acd6bc49ed0b600a4f90a0c00ea20d4cd7bfc9b599131a4d8eed0bcad88cb14e53ddca5269ecc67090540dbdfcbd980bc8083159a3ff7568968aad3c69d368dd005c88842e279d03022cbd4e889fbb4b1741cad3eb9d3d4299223b7442ed30d59f6df90dae29635e2a4a88d44d78b8cefa033adc20c0fba2c49f788dc2f118a6499b91419511e1f2ecb8171bf72f29e69faa04b917c708e4545df9c1181a75a3e42340e3f68fea06986f76a89ffb1343ad76036b7396c63411447494372dd4a34e1176784254798705ca2ce9e71f842660b09bce8a0cb6bc1f258c121ec5c7f97e73bbcd56f279d3607f1d315b0380d051a4b8ea02a44d9ee1f8886c68ef513bbd1e461bf237e1abf1b703989ce6f9a8e495279fdefed04daf77cb02d47a49013f709067d15511fe697cbb93106ba315799aa5802998fd2b1e00aab5cdd12884cbc9cab9f6da92136bbe3085e0e3787d6875f9c08d0acb52f353656926f6104581ec75fe0b7a9a4af091188eb35dfdaeb111ecec9718da6a41de95500f33961b030e4e382216d4d3377547ff3331db29641c7cfddab7dae4dd0927350dfb6882a8e5e1d9951536bd7c13d8ec1bb71663e5914e"

    w3 = SethWeb3Mock(IP, PORT)
    MY_OQS = w3.client.get_oqs_address(OQS_PK)

    test_oqs_transfer(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_contract_deploy_and_call(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_library_with_contract(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_contract_prefund_flow(w3, MY_OQS, OQS_KEY, OQS_PK)

if __name__ == "__main__":
    ecdsa_sign_test()
    oqs_sign_test()
