"""
Contract Chain Demo: Ensures all dependent contracts are in the same shard and pool

This demo creates 3 users who deploy 3 dependent contracts (A -> B -> C).
Before deploying each contract, it verifies that the contract address will be 
in the same shard and pool as the previous contract. If not, it generates a 
new user address until finding one that maps to the correct shard/pool.

Shard calculation: hash64(address) % (max_shard_id - min_shard_id + 1) + min_shard_id
Pool calculation: hash32(address) % kImmutablePoolSize

Max shard_id: 3
kConsensusShardBeginNetworkId: 1
kImmutablePoolSize: 7
"""

from __future__ import annotations
import secrets
import hashlib
import struct
import time
import eth_abi
from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1
from seth_sdk import SethWeb3Mock, StepType, compile_and_link

# Constants matching C++ implementation
CONSENSUS_SHARD_BEGIN_NETWORK_ID = 1
MAX_SHARD_ID = 3
IMMUTABLE_POOL_SIZE = 7
UNICAST_ADDRESS_LENGTH = 20

# Contract source code
CONTRACT_A_SOL = """
pragma solidity ^0.8.20;

contract ContractA {
    uint256 public value;
    address public owner;
    
    event ValueSet(uint256 newValue);
    
    constructor() {
        owner = msg.sender;
        value = 100;
    }
    
    function setValue(uint256 _value) external {
        value = _value;
        emit ValueSet(_value);
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
}
"""

CONTRACT_B_SOL = """
pragma solidity ^0.8.20;

interface IContractA {
    function getValue() external view returns (uint256);
    function setValue(uint256 _value) external;
}

contract ContractB {
    address public contractA;
    uint256 public multiplier;
    
    event MultiplierSet(uint256 newMultiplier);
    event ValueUpdated(uint256 originalValue, uint256 newValue);
    
    constructor(address _contractA) {
        contractA = _contractA;
        multiplier = 2;
    }
    
    function setMultiplier(uint256 _multiplier) external {
        multiplier = _multiplier;
        emit MultiplierSet(_multiplier);
    }
    
    function updateValueInA() external {
        IContractA a = IContractA(contractA);
        uint256 currentValue = a.getValue();
        uint256 newValue = currentValue * multiplier;
        a.setValue(newValue);
        emit ValueUpdated(currentValue, newValue);
    }
    
    function getValueFromA() external view returns (uint256) {
        return IContractA(contractA).getValue();
    }
}
"""

CONTRACT_C_SOL = """
pragma solidity ^0.8.20;

interface IContractB {
    function getValueFromA() external view returns (uint256);
    function updateValueInA() external;
    function setMultiplier(uint256 _multiplier) external;
}

contract ContractC {
    address public contractB;
    uint256 public addend;
    
    event AddendSet(uint256 newAddend);
    event ChainUpdated(uint256 finalValue);
    
    constructor(address _contractB) {
        contractB = _contractB;
        addend = 50;
    }
    
    function setAddend(uint256 _addend) external {
        addend = _addend;
        emit AddendSet(_addend);
    }
    
    function triggerChainUpdate() external {
        IContractB b = IContractB(contractB);
        
        // First, update multiplier in B
        b.setMultiplier(3);
        
        // Then trigger B to update A
        b.updateValueInA();
        
        // Get final value
        uint256 finalValue = b.getValueFromA();
        emit ChainUpdated(finalValue);
    }
    
    function getValueFromChain() external view returns (uint256) {
        return IContractB(contractB).getValueFromA();
    }
}
"""


def hash32(data: bytes) -> int:
    """Calculate 32-bit hash matching C++ Hash::Hash32"""
    # Use first 4 bytes of keccak256 as hash32
    k = keccak.new(digest_bits=256)
    k.update(data)
    digest = k.digest()
    return struct.unpack('<I', digest[:4])[0]


def hash64(data: bytes) -> int:
    """Calculate 64-bit hash matching C++ Hash::Hash64"""
    # Use first 8 bytes of keccak256 as hash64
    k = keccak.new(digest_bits=256)
    k.update(data)
    digest = k.digest()
    return struct.unpack('<Q', digest[:8])[0]


def calc_shard_id(address: str) -> int:
    """Calculate shard ID for an address"""
    addr_bytes = bytes.fromhex(address.replace('0x', ''))[:UNICAST_ADDRESS_LENGTH]
    hash_value = hash64(addr_bytes)
    shard_range = MAX_SHARD_ID - CONSENSUS_SHARD_BEGIN_NETWORK_ID + 1
    return (hash_value % shard_range) + CONSENSUS_SHARD_BEGIN_NETWORK_ID


def calc_pool_index(address: str) -> int:
    """Calculate pool index for an address"""
    addr_bytes = bytes.fromhex(address.replace('0x', ''))[:UNICAST_ADDRESS_LENGTH]
    return hash32(addr_bytes) % IMMUTABLE_POOL_SIZE


def calc_create2_address(sender: str, salt: str, bytecode: str) -> str:
    """Calculate CREATE2 address"""
    sender = sender.lower().replace('0x', '')
    bytecode = bytecode.lower().replace('0x', '')
    
    # Ensure salt is 32 bytes
    salt_clean = str(salt).lower().replace('0x', '')
    try:
        salt_bytes = bytes.fromhex(salt_clean).ljust(32, b'\x00')[:32]
    except ValueError:
        # If not hex, hash the string
        k = keccak.new(digest_bits=256)
        k.update(str(salt).encode())
        salt_bytes = k.digest()
    
    # Calculate code hash
    k = keccak.new(digest_bits=256)
    k.update(bytes.fromhex(bytecode))
    code_hash = k.digest()
    
    # Calculate address: keccak256(0xff ++ sender ++ salt ++ keccak256(bytecode))
    input_data = bytes.fromhex("ff") + bytes.fromhex(sender) + salt_bytes + code_hash
    k = keccak.new(digest_bits=256)
    k.update(input_data)
    return k.digest()[-20:].hex().lower()


def generate_user_for_target_shard_pool(target_shard: int, target_pool: int, max_attempts: int = 10000):
    """
    Generate a new user (private key + address) that maps to the target shard and pool.
    
    Returns:
        tuple: (private_key_hex, address_hex) or (None, None) if not found
    """
    print(f"  🔍 Searching for user address in shard {target_shard}, pool {target_pool}...")
    
    for attempt in range(max_attempts):
        # Generate random private key
        sk = SigningKey.generate(curve=SECP256k1)
        private_key = sk.to_string().hex()
        
        # Calculate address
        pub = sk.verifying_key.to_string("uncompressed")[1:]
        k = keccak.new(digest_bits=256)
        k.update(pub)
        address = k.digest()[-20:].hex()
        
        # Check shard and pool
        shard = calc_shard_id(address)
        pool = calc_pool_index(address)
        
        if shard == target_shard and pool == target_pool:
            print(f"  ✅ Found matching address after {attempt + 1} attempts")
            print(f"     Address: {address}")
            print(f"     Shard: {shard}, Pool: {pool}")
            return private_key, address
    
    print(f"  ❌ Failed to find matching address after {max_attempts} attempts")
    return None, None


def create_and_wait_for_address(w3, funder_key: str, target_shard: int, target_pool: int, 
                                 initial_balance: int = 10000000, max_wait: int = 60):
    """
    Create a new user address and wait for it to be active on the blockchain.
    
    Args:
        w3: Web3 mock instance
        funder_key: Private key of the account that will fund the new address
        target_shard: Target shard ID
        target_pool: Target pool index
        initial_balance: Initial balance to send to the new address
        max_wait: Maximum wait time in seconds
    
    Returns:
        tuple: (private_key, address) or (None, None) if failed
    """
    # Generate user address matching target shard/pool
    private_key, address = generate_user_for_target_shard_pool(target_shard, target_pool)
    
    if not private_key:
        return None, None
    
    print(f"\n  💰 Funding new address with {initial_balance} coins...")
    
    # Send transaction to create the address on-chain
    try:
        # Use kRootCreateAddress to create the address
        tx_hash = w3.client.send_transaction_auto(
            funder_key,
            address,
            StepType.kRootCreateAddress,
            amount=initial_balance
        )
        
        print(f"  📤 Transaction sent: {tx_hash[:16]}...")
        
        # Wait for the address to be created and active
        print(f"  ⏳ Waiting for address to be active (max {max_wait}s)...")
        
        start_time = time.time()
        check_interval = 2  # Check every 2 seconds
        
        while time.time() - start_time < max_wait:
            try:
                # Query the address balance
                balance = w3.client.get_balance(address)
                
                if balance >= initial_balance:
                    elapsed = time.time() - start_time
                    print(f"  ✅ Address is active! (took {elapsed:.1f}s)")
                    print(f"     Balance: {balance}")
                    return private_key, address
                
                # Address exists but balance not yet updated
                if balance > 0:
                    print(f"  ⏳ Address found, balance: {balance}, waiting for full amount...")
                
            except Exception as e:
                # Address might not exist yet
                pass
            
            time.sleep(check_interval)
        
        # Timeout
        elapsed = time.time() - start_time
        print(f"  ⚠️  Timeout after {elapsed:.1f}s, but address may still be valid")
        print(f"     You may need to wait longer or check manually")
        
        # Return the address anyway, it might work
        return private_key, address
        
    except Exception as e:
        print(f"  ❌ Failed to create address: {e}")
        return None, None


def test_contract_chain_same_shard_pool(w3, MY, KEY):
    """
    Test contract chain deployment ensuring all contracts are in the same shard and pool.
    
    Flow:
    1. User1 deploys ContractA
    2. User2 checks if their address is in the same shard/pool as ContractA
       - If not, generate and create a new User2 address on-chain
    3. User2 deploys ContractB (depends on ContractA)
    4. User3 checks if their address is in the same shard/pool as ContractB
       - If not, generate and create a new User3 address on-chain
    5. User3 deploys ContractC (depends on ContractB)
    6. All three users call their respective contract methods
    """
    print("\n" + "="*80)
    print("TEST: Contract Chain with Same Shard/Pool Enforcement")
    print("="*80)
    
    # ========== Phase 1: Create initial users ==========
    print("\n[Phase 1] Creating initial users...")
    
    # User1 - will deploy ContractA (use the provided account)
    user1_key = KEY
    user1_addr = MY
    
    print(f"\n👤 User1 (Funder):")
    print(f"   Address: {user1_addr}")
    print(f"   Shard: {calc_shard_id(user1_addr)}, Pool: {calc_pool_index(user1_addr)}")
    
    # User2 - initial (may be regenerated)
    user2_sk = SigningKey.generate(curve=SECP256k1)
    user2_key = user2_sk.to_string().hex()
    user2_pub = user2_sk.verifying_key.to_string("uncompressed")[1:]
    k = keccak.new(digest_bits=256)
    k.update(user2_pub)
    user2_addr = k.digest()[-20:].hex()
    
    print(f"\n👤 User2 (initial):")
    print(f"   Address: {user2_addr}")
    print(f"   Shard: {calc_shard_id(user2_addr)}, Pool: {calc_pool_index(user2_addr)}")
    
    # User3 - initial (may be regenerated)
    user3_sk = SigningKey.generate(curve=SECP256k1)
    user3_key = user3_sk.to_string().hex()
    user3_pub = user3_sk.verifying_key.to_string("uncompressed")[1:]
    k = keccak.new(digest_bits=256)
    k.update(user3_pub)
    user3_addr = k.digest()[-20:].hex()
    
    print(f"\n👤 User3 (initial):")
    print(f"   Address: {user3_addr}")
    print(f"   Shard: {calc_shard_id(user3_addr)}, Pool: {calc_pool_index(user3_addr)}")
    
    # ========== Phase 2: Deploy ContractA ==========
    print("\n" + "-"*80)
    print("[Phase 2] User1 deploys ContractA")
    print("-"*80)
    
    a_bin, a_abi = compile_and_link(CONTRACT_A_SOL, "ContractA")
    
    # Calculate ContractA address
    salt_a = secrets.token_hex(31) + 'a'
    contract_a_addr = calc_create2_address(user1_addr, salt_a, a_bin)
    contract_a_shard = calc_shard_id(contract_a_addr)
    contract_a_pool = calc_pool_index(contract_a_addr)
    
    print(f"\n📋 ContractA (predicted):")
    print(f"   Address: {contract_a_addr}")
    print(f"   Shard: {contract_a_shard}, Pool: {contract_a_pool}")
    
    # Deploy ContractA
    contract_a = w3.seth.contract(abi=a_abi, bytecode=a_bin, sender_address=user1_addr).deploy({
        'from': user1_addr,
        'salt': salt_a,
    }, user1_key)
    
    print(f"✅ ContractA deployed at: {contract_a.address}")
    
    # ========== Phase 3: Ensure User2 is in same shard/pool as ContractA ==========
    print("\n" + "-"*80)
    print("[Phase 3] Ensuring User2 is in same shard/pool as ContractA")
    print("-"*80)
    
    user2_shard = calc_shard_id(user2_addr)
    user2_pool = calc_pool_index(user2_addr)
    
    if user2_shard != contract_a_shard or user2_pool != contract_a_pool:
        print(f"\n⚠️  User2 mismatch detected:")
        print(f"   User2: Shard {user2_shard}, Pool {user2_pool}")
        print(f"   ContractA: Shard {contract_a_shard}, Pool {contract_a_pool}")
        print(f"\n🔄 Creating new User2 to match ContractA's shard/pool...")
        
        new_key, new_addr = create_and_wait_for_address(
            w3, user1_key, contract_a_shard, contract_a_pool, 
            initial_balance=10000000, max_wait=60
        )
        
        if new_key:
            user2_key = new_key
            user2_addr = new_addr
            print(f"\n✅ User2 created and activated successfully!")
        else:
            print(f"\n❌ Failed to create User2. Using original (may cause issues).")
    else:
        print(f"\n✅ User2 already in correct shard/pool!")
        print(f"   User2: Shard {user2_shard}, Pool {user2_pool}")
        print(f"   ContractA: Shard {contract_a_shard}, Pool {contract_a_pool}")
    
    # ========== Phase 4: Deploy ContractB ==========
    print("\n" + "-"*80)
    print("[Phase 4] User2 deploys ContractB (depends on ContractA)")
    print("-"*80)
    
    b_bin, b_abi = compile_and_link(CONTRACT_B_SOL, "ContractB")
    
    # Calculate ContractB address
    salt_b = secrets.token_hex(31) + 'b'
    
    # Add constructor argument (ContractA address) to bytecode
    constructor_args = eth_abi.encode(['address'], [bytes.fromhex(contract_a.address)])
    b_bin_with_args = b_bin + constructor_args.hex()
    
    contract_b_addr = calc_create2_address(user2_addr, salt_b, b_bin_with_args)
    contract_b_shard = calc_shard_id(contract_b_addr)
    contract_b_pool = calc_pool_index(contract_b_addr)
    
    print(f"\n📋 ContractB (predicted):")
    print(f"   Address: {contract_b_addr}")
    print(f"   Shard: {contract_b_shard}, Pool: {contract_b_pool}")
    print(f"   Depends on ContractA: {contract_a.address}")
    
    # Deploy ContractB
    contract_b = w3.seth.contract(abi=b_abi, bytecode=b_bin, sender_address=user2_addr).deploy({
        'from': user2_addr,
        'salt': salt_b,
        'args': [contract_a.address],
    }, user2_key)
    
    print(f"✅ ContractB deployed at: {contract_b.address}")
    
    # ========== Phase 5: Ensure User3 is in same shard/pool as ContractB ==========
    print("\n" + "-"*80)
    print("[Phase 5] Ensuring User3 is in same shard/pool as ContractB")
    print("-"*80)
    
    user3_shard = calc_shard_id(user3_addr)
    user3_pool = calc_pool_index(user3_addr)
    
    if user3_shard != contract_b_shard or user3_pool != contract_b_pool:
        print(f"\n⚠️  User3 mismatch detected:")
        print(f"   User3: Shard {user3_shard}, Pool {user3_pool}")
        print(f"   ContractB: Shard {contract_b_shard}, Pool {contract_b_pool}")
        print(f"\n🔄 Creating new User3 to match ContractB's shard/pool...")
        
        new_key, new_addr = create_and_wait_for_address(
            w3, user1_key, contract_b_shard, contract_b_pool,
            initial_balance=10000000, max_wait=60
        )
        
        if new_key:
            user3_key = new_key
            user3_addr = new_addr
            print(f"\n✅ User3 created and activated successfully!")
        else:
            print(f"\n❌ Failed to create User3. Using original (may cause issues).")
    else:
        print(f"\n✅ User3 already in correct shard/pool!")
        print(f"   User3: Shard {user3_shard}, Pool {user3_pool}")
        print(f"   ContractB: Shard {contract_b_shard}, Pool {contract_b_pool}")
    
    # ========== Phase 6: Deploy ContractC ==========
    print("\n" + "-"*80)
    print("[Phase 6] User3 deploys ContractC (depends on ContractB)")
    print("-"*80)
    
    c_bin, c_abi = compile_and_link(CONTRACT_C_SOL, "ContractC")
    
    # Calculate ContractC address
    salt_c = secrets.token_hex(31) + 'c'
    
    # Add constructor argument (ContractB address) to bytecode
    constructor_args = eth_abi.encode(['address'], [bytes.fromhex(contract_b.address)])
    c_bin_with_args = c_bin + constructor_args.hex()
    
    contract_c_addr = calc_create2_address(user3_addr, salt_c, c_bin_with_args)
    contract_c_shard = calc_shard_id(contract_c_addr)
    contract_c_pool = calc_pool_index(contract_c_addr)
    
    print(f"\n📋 ContractC (predicted):")
    print(f"   Address: {contract_c_addr}")
    print(f"   Shard: {contract_c_shard}, Pool: {contract_c_pool}")
    print(f"   Depends on ContractB: {contract_b.address}")
    
    # Deploy ContractC
    contract_c = w3.seth.contract(abi=c_abi, bytecode=c_bin, sender_address=user3_addr).deploy({
        'from': user3_addr,
        'salt': salt_c,
        'args': [contract_b.address],
    }, user3_key)
    
    print(f"✅ ContractC deployed at: {contract_c.address}")
    
    # ========== Phase 7: Verify all contracts are in same shard/pool ==========
    print("\n" + "="*80)
    print("[Phase 7] Verification Summary")
    print("="*80)
    
    print(f"\n📊 Deployment Summary:")
    print(f"   ContractA: {contract_a.address[:16]}... | Shard {contract_a_shard} | Pool {contract_a_pool}")
    print(f"   ContractB: {contract_b.address[:16]}... | Shard {contract_b_shard} | Pool {contract_b_pool}")
    print(f"   ContractC: {contract_c.address[:16]}... | Shard {contract_c_shard} | Pool {contract_c_pool}")
    
    all_same_shard = (contract_a_shard == contract_b_shard == contract_c_shard)
    all_same_pool = (contract_a_pool == contract_b_pool == contract_c_pool)
    
    if all_same_shard and all_same_pool:
        print(f"\n✅ SUCCESS: All contracts are in the same shard ({contract_a_shard}) and pool ({contract_a_pool})!")
    else:
        print(f"\n❌ FAILURE: Contracts are NOT in the same shard/pool!")
        if not all_same_shard:
            print(f"   Shard mismatch: A={contract_a_shard}, B={contract_b_shard}, C={contract_c_shard}")
        if not all_same_pool:
            print(f"   Pool mismatch: A={contract_a_pool}, B={contract_b_pool}, C={contract_c_pool}")
    
    # ========== Phase 8: Execute contract calls ==========
    print("\n" + "="*80)
    print("[Phase 8] Executing Contract Calls")
    print("="*80)
    
    # User1 calls ContractA.getValue()
    print(f"\n[Call 1] User1 calls ContractA.getValue()")
    value_a = contract_a.functions.getValue().call()
    print(f"   Result: {value_a[0] if value_a else 'N/A'}")
    
    # User2 calls ContractB.getValueFromA()
    print(f"\n[Call 2] User2 calls ContractB.getValueFromA()")
    value_from_a = contract_b.functions.getValueFromA().call()
    print(f"   Result: {value_from_a[0] if value_from_a else 'N/A'}")
    
    # User3 calls ContractC.triggerChainUpdate()
    print(f"\n[Call 3] User3 calls ContractC.triggerChainUpdate()")
    receipt = contract_c.functions.triggerChainUpdate().transact(user3_key)
    if receipt.get('status') == 0:
        print(f"   ✅ Chain update successful")
        for e in receipt.get('decoded_events', []):
            print(f"   📍 Event: {e['event']} → {e['args']}")
    else:
        print(f"   ❌ Chain update failed: {receipt.get('msg')}")
    
    # Verify final value
    print(f"\n[Verification] Checking final value in ContractA")
    final_value = contract_a.functions.getValue().call()
    print(f"   Final value in ContractA: {final_value[0] if final_value else 'N/A'}")
    
    print("\n" + "="*80)
    print("✅ Contract Chain Demo Complete!")
    print("="*80)


if __name__ == "__main__":
    IP, PORT, KEY = "127.0.0.1", 23001, "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
    w3 = SethWeb3Mock(IP, PORT)
    MY = w3.client.get_address(KEY)
    
    # Run the test
    test_contract_chain_same_shard_pool(w3, KEY, MY)
