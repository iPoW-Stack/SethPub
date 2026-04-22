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
import requests
import eth_abi
import xxhash
from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1
from seth_sdk import SethWeb3Mock, StepType, compile_and_link

# Constants matching C++ implementation
CONSENSUS_SHARD_BEGIN_NETWORK_ID = 3
MAX_SHARD_ID = 3
IMMUTABLE_POOL_SIZE = 32
UNICAST_ADDRESS_LENGTH = 20

# Hash seeds from C++ (src/common/hash.h)
HASH_SEED_U32 = 623453345
HASH_SEED_1 = 23456785675590
kInitAccountMount = 100000000

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
    """Calculate 32-bit hash matching C++ Hash::Hash32 using xxHash"""
    return xxhash.xxh32(data, seed=HASH_SEED_U32).intdigest()


def hash64(data: bytes) -> int:
    """Calculate 64-bit hash matching C++ Hash::Hash64 using xxHash"""
    return xxhash.xxh64(data, seed=HASH_SEED_1).intdigest()


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


def generate_user_for_target_shard_pool(target_shard: int, target_pool: int, max_attempts: int = 100000):
    """
    Generate a new user (private key + address) that maps to the target shard and pool.
    
    Returns:
        tuple: (private_key_hex, address_hex) or (None, None) if not found
    """
    print(f"  🔍 Searching for user address in shard {target_shard}, pool {target_pool}...")
    
    # Calculate expected probability
    shard_range = MAX_SHARD_ID - CONSENSUS_SHARD_BEGIN_NETWORK_ID + 1
    expected_attempts = shard_range * IMMUTABLE_POOL_SIZE
    print(f"     Expected attempts: ~{expected_attempts} (shard_range={shard_range}, pool_size={IMMUTABLE_POOL_SIZE})")
    
    for attempt in range(max_attempts):
        # Generate random private key
        sk = SigningKey.generate(curve=SECP256k1)
        private_key = sk.to_string().hex()
        
        # Calculate address
        pub = sk.verifying_key.to_string("uncompressed")[1:]
        k = keccak.new(digest_bits=256)
        k.update(pub)
        address = k.digest()[-20:].hex()
        if target_shard == 0:
            return private_key, address
        
        # Check shard and pool
        shard = calc_shard_id(address)
        pool = calc_pool_index(address)
        
        if shard == target_shard and pool == target_pool:
            print(f"  ✅ Found matching address after {attempt + 1} attempts")
            print(f"     Address: {address}")
            print(f"     Shard: {shard}, Pool: {pool}")
            return private_key, address
        
        # Progress indicator every 10000 attempts
        if (attempt + 1) % 10000 == 0:
            print(f"     Progress: {attempt + 1}/{max_attempts} attempts...")
    
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
        tuple: (private_key, address, actual_info) or (None, None, None) if failed
        actual_info is a dict with 'shard_id' and 'pool_index' from blockchain
    """
    # Generate user address matching target shard/pool
    private_key, address = generate_user_for_target_shard_pool(target_shard, target_pool)
    
    if not private_key:
        return None, None, None
    
    print(f"\n  💰 Funding new address with {initial_balance} coins...")
    
    # Send transaction to create the address on-chain
    try:
        # Use kNormalFrom for standard transfer to create the address
        tx_hash = w3.client.send_transaction_auto(
            funder_key,
            address,
            StepType.kNormalFrom,
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
                    
                    # Query actual shard/pool from blockchain
                    actual_info = query_address_info(w3, address, max_wait=30)
                    
                    if actual_info:
                        print(f"  📊 Blockchain Info:")
                        print(f"     Address: {address}")
                        print(f"     Shard: {actual_info['shard_id']}, Pool: {actual_info['pool_index']}")
                        print(f"     Balance: {actual_info['balance']}")
                        return private_key, address, actual_info
                    else:
                        print(f"  ⚠️  Could not query shard/pool info")
                        return private_key, address, None
                
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
        return private_key, address, None
        
    except Exception as e:
        print(f"  ❌ Failed to create address: {e}")
        return None, None, None


def query_address_info(w3, address: str, max_wait: int = 60):
    """
    Query address information from the blockchain, including shard and pool.
    
    Args:
        w3: Web3 mock instance
        address: Address to query (without 0x prefix)
        max_wait: Maximum wait time in seconds
    
    Returns:
        dict: Address info with 'shard_id' and 'pool_index', or None if failed
    """
    print(f"  🔍 Querying address info from blockchain...")
    
    # Clean address format
    clean_addr = address.replace('0x', '')
    
    start_time = time.time()
    check_interval = 2
    
    while time.time() - start_time < max_wait:
        try:
            # Use the query_url from the client
            result = requests.post(
                w3.client.query_url, 
                data={"address": clean_addr}, 
                timeout=5, 
                verify=w3.client.verify_ssl
            )
            
            if result.status_code == 200:
                data = result.json()
                
                # Check if address exists and has shard/pool info
                # API returns camelCase: 'shardingId' and 'poolIndex'
                shard_id = data.get('shardingId') or data.get('sharding_id') or data.get('shard_id')
                pool_index = data.get('poolIndex') or data.get('pool_index')
                
                if shard_id is not None and pool_index is not None:
                    elapsed = time.time() - start_time
                    print(f"  ✅ Address info retrieved! (took {elapsed:.1f}s)")
                    print(f"     Shard: {shard_id}, Pool: {pool_index}")
                    print(f"     Balance: {data.get('balance', 0)}")
                    return {
                        'shard_id': int(shard_id),
                        'pool_index': int(pool_index),
                        'balance': int(data.get('balance', 0)),
                        'nonce': int(data.get('nonce', 0))
                    }
                else:
                    # Address exists but no shard/pool info yet
                    print(f"  ⏳ Address found but shard/pool not yet assigned...")
                    print(f"     Debug: data keys = {list(data.keys())}")
                    
        except requests.exceptions.RequestException as e:
            print(f"  ⚠️  Request error: {e}")
        except Exception as e:
            print(f"  ⚠️  Parse error: {e}")
        
        time.sleep(check_interval)
    
    # Timeout - return None
    elapsed = time.time() - start_time
    print(f"  ⚠️  Timeout after {elapsed:.1f}s, could not retrieve address info")
    return None


def test_contract_chain_same_shard_pool(w3, MY, KEY):
    """
    Test contract chain deployment ensuring all contracts are in the same shard and pool.
    
    Flow:
    0. 准备 User1（资金提供者）
    1. 预先创建 User2 和 User3（通过转币交易）并验证链上合法
    2. User1 deploys ContractA (直接部署，不做任何检查)
    3. 根据 ContractA 的 shard/pool 确定目标位置
    4. 检查 User2 是否与目标在同一 shard/pool
       - 如果不是，重新生成并创建新 User2
    5. User2 部署 ContractB (依赖 ContractA)
    6. 检查 User3 是否与目标在同一 shard/pool
       - 如果不是，重新生成并创建新 User3
    7. User3 部署 ContractC (依赖 ContractB)
    8. 验证所有合约在同一 shard/pool
    9. 执行合约调用链
    """
    print("\n" + "="*80)
    print("TEST: Contract Chain with Same Shard/Pool Enforcement")
    print("="*80)
    
    # ========== Phase 0: 准备 User1 ==========
    print("\n[Phase 0] Preparing User1 (Funder)")
    
    # User1 - 使用提供的账户作为资金提供者
    user1_key = KEY
    user1_addr = MY
    
    print("\n👤 User1 (Funder):")
    print(f"   Address: {user1_addr}")
    
    # ========== Phase 1: 预先创建 User2 和 User3 ==========
    print("\n" + "="*80)
    print("[Phase 1] Pre-creating User2 and User3 on-chain")
    print("="*80)
    
    print("\n[1.1] Creating User2...")
    # 生成随机 User2
    user2_sk = SigningKey.generate(curve=SECP256k1)
    user2_key = user2_sk.to_string().hex()
    user2_pub = user2_sk.verifying_key.to_string("uncompressed")[1:]
    k = keccak.new(digest_bits=256)
    k.update(user2_pub)
    user2_addr = k.digest()[-20:].hex()
    
    # 通过转币交易创建 User2
    user2_key, user2_addr, user2_info = create_and_wait_for_address(
        w3, user1_key, 0, 0,  # target不重要，会从链上查询
        initial_balance=kInitAccountMount, max_wait=60
    )
    
    if not user2_key:
        print(f"  ❌ Failed to create User2")
        return
    
    print(f"  ✅ User2 created and verified on-chain")
    
    print("\n[1.2] Creating User3...")
    # 生成随机 User3
    user3_sk = SigningKey.generate(curve=SECP256k1)
    user3_key = user3_sk.to_string().hex()
    user3_pub = user3_sk.verifying_key.to_string("uncompressed")[1:]
    k = keccak.new(digest_bits=256)
    k.update(user3_pub)
    user3_addr = k.digest()[-20:].hex()
    
    # 通过转币交易创建 User3
    user3_key, user3_addr, user3_info = create_and_wait_for_address(
        w3, user1_key, 0, 0,  # target不重要，会从链上查询
        initial_balance=kInitAccountMount, max_wait=60
    )
    
    if not user3_key:
        print(f"  ❌ Failed to create User3")
        return
    
    print(f"  ✅ User3 created and verified on-chain")
    
    print("\n" + "="*80)
    print("✅ User2 and User3 are now valid on-chain")
    print("="*80)
    
    # ========== Phase 2: 直接部署 ContractA ==========
    print("\n" + "-"*80)
    print("[Phase 2] User1 deploys ContractA")
    print("-"*80)
    
    a_bin, a_abi = compile_and_link(CONTRACT_A_SOL, "ContractA")
    
    # Deploy ContractA directly
    salt_a = secrets.token_hex(31) + 'a'
    contract_a = w3.seth.contract(abi=a_abi, bytecode=a_bin, sender_address=user1_addr).deploy({
        'from': user1_addr,
        'salt': salt_a,
    }, user1_key)
    
    print(f"\n✅ ContractA deployed")
    
    # Query actual shard/pool from blockchain
    print(f"\n🔍 Querying ContractA's actual shard/pool from blockchain...")
    contract_a_info = query_address_info(w3, contract_a.address, max_wait=60)
    
    if contract_a_info:
        target_shard = contract_a_info['shard_id']
        target_pool = contract_a_info['pool_index']
        
        print(f"\n📊 ContractA Blockchain Info:")
        print(f"   Address: {contract_a.address}")
        print(f"   Shard: {target_shard}, Pool: {target_pool}")
        print(f"   Balance: {contract_a_info['balance']}")
    else:
        print(f"\n❌ Could not query ContractA info from blockchain")
        return
    
    print(f"\n🎯 Target shard/pool determined:")
    print(f"   Target Shard: {target_shard}")
    print(f"   Target Pool: {target_pool}")
    
    # ========== Phase 3: 检查并可能重新创建 User2 ==========
    print("\n" + "-"*80)
    print("[Phase 3] Checking User2 compatibility with target shard/pool")
    print("-"*80)
    
    print(f"\n👤 Current User2:")
    print(f"   Address: {user2_addr}")
    print(f"   Shard: {user2_info['shard_id']}, Pool: {user2_info['pool_index']}")
    
    # 检查是否需要重新生成
    if user2_info['shard_id'] != target_shard or user2_info['pool_index'] != target_pool:
        print(f"\n⚠️  User2 mismatch detected:")
        print(f"   User2: Shard {user2_info['shard_id']}, Pool: {user2_info['pool_index']}")
        print(f"   Target: Shard {target_shard}, Pool {target_pool}")
        print(f"\n🔄 Creating new User2 to match target shard/pool...")
        print(f"   Using old User2 to fund the new User2...")
        
        # 用旧的 User2 去转账创建新的 User2
        new_key, new_addr, new_info = create_and_wait_for_address(
            w3, user2_key, target_shard, target_pool, 
            initial_balance=int(kInitAccountMount / 2), max_wait=60
        )
        
        if new_key and new_info:
            user2_key = new_key
            user2_addr = new_addr
            user2_info = new_info
            print(f"\n✅ New User2 created and activated successfully!")
        else:
            print(f"\n❌ Failed to create new User2. Using original (may cause issues).")
    else:
        print(f"\n✅ User2 already in correct shard/pool!")
        print(f"   No need to regenerate")
    
    # ========== Phase 4: Deploy ContractB ==========
    print("\n" + "-"*80)
    print("[Phase 4] User2 deploys ContractB (depends on ContractA)")
    print("-"*80)
    
    b_bin, b_abi = compile_and_link(CONTRACT_B_SOL, "ContractB")
    
    # Deploy ContractB
    salt_b = secrets.token_hex(31) + 'b'
    contract_b = w3.seth.contract(abi=b_abi, bytecode=b_bin, sender_address=user2_addr).deploy({
        'from': user2_addr,
        'salt': salt_b,
        'args': [contract_a.address],
    }, user2_key)
    
    print(f"\n✅ ContractB deployed")
    
    # Query actual shard/pool from blockchain
    print(f"\n🔍 Querying ContractB's info from blockchain...")
    contract_b_info = query_address_info(w3, contract_b.address, max_wait=60)
    
    if contract_b_info:
        print(f"\n� ContractB Blockchain Info:")
        print(f"   Address: {contract_b.address}")
        print(f"   Shard: {contract_b_info['shard_id']}, Pool: {contract_b_info['pool_index']}")
        print(f"   Depends on ContractA: {contract_a.address}")
    
    # ========== Phase 5: 检查并可能重新创建 User3 ==========
    print("\n" + "-"*80)
    print("[Phase 5] Checking User3 compatibility with target shard/pool")
    print("-"*80)
    
    print(f"\n👤 Current User3:")
    print(f"   Address: {user3_addr}")
    print(f"   Shard: {user3_info['shard_id']}, Pool: {user3_info['pool_index']}")
    
    # 检查是否需要重新生成
    if user3_info['shard_id'] != target_shard or user3_info['pool_index'] != target_pool:
        print(f"\n⚠️  User3 mismatch detected:")
        print(f"   User3: Shard {user3_info['shard_id']}, Pool {user3_info['pool_index']}")
        print(f"   Target: Shard {target_shard}, Pool {target_pool}")
        print(f"\n🔄 Creating new User3 to match target shard/pool...")
        print(f"   Using old User3 to fund the new User3...")
        
        # 用旧的 User3 去转账创建新的 User3
        new_key, new_addr, new_info = create_and_wait_for_address(
            w3, user3_key, target_shard, target_pool,
            initial_balance=int(kInitAccountMount / 2), max_wait=60
        )
        
        if new_key and new_info:
            user3_key = new_key
            user3_addr = new_addr
            user3_info = new_info
            print(f"\n✅ New User3 created and activated successfully!")
        else:
            print(f"\n❌ Failed to create new User3. Using original (may cause issues).")
    else:
        print(f"\n✅ User3 already in correct shard/pool!")
        print(f"   No need to regenerate")
    
    # ========== Phase 6: Deploy ContractC ==========
    print("\n" + "-"*80)
    print("[Phase 6] User3 deploys ContractC (depends on ContractB)")
    print("-"*80)
    
    c_bin, c_abi = compile_and_link(CONTRACT_C_SOL, "ContractC")
    
    # Deploy ContractC
    salt_c = secrets.token_hex(31) + 'c'
    contract_c = w3.seth.contract(abi=c_abi, bytecode=c_bin, sender_address=user3_addr).deploy({
        'from': user3_addr,
        'salt': salt_c,
        'args': [contract_b.address],
    }, user3_key)
    
    print(f"\n✅ ContractC deployed")
    
    # Query actual shard/pool from blockchain
    print(f"\n🔍 Querying ContractC's info from blockchain...")
    contract_c_info = query_address_info(w3, contract_c.address, max_wait=60)
    
    if contract_c_info:
        print(f"\n� ContractC Blockchain Info:")
        print(f"   Address: {contract_c.address}")
        print(f"   Shard: {contract_c_info['shard_id']}, Pool: {contract_c_info['pool_index']}")
        print(f"   Depends on ContractB: {contract_b.address}")
    
    # ========== Phase 7: Verify all contracts are in same shard/pool ==========
    print("\n" + "="*80)
    print("[Phase 7] Verification Summary")
    print("="*80)
    
    print(f"\n📊 Deployment Summary:")
    print(f"   ContractA: {contract_a.address[:16]}... | Shard {contract_a_info['shard_id']} | Pool {contract_a_info['pool_index']}")
    print(f"   ContractB: {contract_b.address[:16]}... | Shard {contract_b_info['shard_id']} | Pool {contract_b_info['pool_index']}")
    print(f"   ContractC: {contract_c.address[:16]}... | Shard {contract_c_info['shard_id']} | Pool {contract_c_info['pool_index']}")
    
    all_same_shard = (contract_a_info['shard_id'] == contract_b_info['shard_id'] == contract_c_info['shard_id'])
    all_same_pool = (contract_a_info['pool_index'] == contract_b_info['pool_index'] == contract_c_info['pool_index'])
    
    if all_same_shard and all_same_pool:
        print(f"\n✅ SUCCESS: All contracts are in the same shard ({contract_a_info['shard_id']}) and pool ({contract_a_info['pool_index']})!")
    else:
        print(f"\n❌ FAILURE: Contracts are NOT in the same shard/pool!")
        if not all_same_shard:
            print(f"   Shard mismatch: A={contract_a_info['shard_id']}, B={contract_b_info['shard_id']}, C={contract_c_info['shard_id']}")
        if not all_same_pool:
            print(f"   Pool mismatch: A={contract_a_info['pool_index']}, B={contract_b_info['pool_index']}, C={contract_c_info['pool_index']}")
    
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
    IP, PORT, KEY = "127.0.0.1", 23001, "7c5b4ec643cfe561eba395569a41c04697920688e2daa4535e30969ffc8a4f66"
    w3 = SethWeb3Mock(IP, PORT)
    MY = w3.client.get_address(KEY)
    
    # Run the test
    test_contract_chain_same_shard_pool(w3, MY, KEY)
