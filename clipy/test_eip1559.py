#!/usr/bin/env python3
"""
EIP-1559 Transaction Test for Seth Blockchain

This script demonstrates sending EIP-1559 (Type 2) transactions to Seth blockchain.
EIP-1559 introduces:
- maxFeePerGas: Maximum fee per gas unit
- maxPriorityFeePerGas: Maximum priority fee (tip) per gas unit
- Dynamic base fee mechanism

Usage:
    python test_eip1559.py --host 127.0.0.1 --port 23001 --key <private_key>
"""

import sys
import time
import secrets

# Import from seth3 instead of seth_sdk
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seth3 import SethWeb3Mock, compile_and_link, _eth_sign_and_send

# Simple test contract
TEST_CONTRACT_SOL = """
pragma solidity ^0.8.20;

contract EIP1559Test {
    uint256 public value;
    address public sender;
    
    event ValueSet(address indexed setter, uint256 newValue, uint256 gasPrice);
    
    constructor() payable {
        sender = msg.sender;
    }
    
    function setValue(uint256 _value) external {
        value = _value;
        sender = msg.sender;
        emit ValueSet(msg.sender, _value, tx.gasprice);
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
}
"""


def test_eip1559_transfer(w3, MY, KEY):
    """
    Test EIP-1559 native token transfer
    """
    print("\n" + "=" * 70)
    print("TEST CASE 1: EIP-1559 Native Token Transfer")
    print("=" * 70)
    
    # Recipient address
    recipient = secrets.token_hex(20)
    transfer_amount = 1000000
    
    print(f"\n[1] Preparing EIP-1559 transfer...")
    print(f"    From: {MY}")
    print(f"    To: {recipient}")
    print(f"    Amount: {transfer_amount}")
    
    # Get initial balances
    balance_before = w3.client.get_balance(recipient)
    print(f"    Recipient balance before: {balance_before}")
    
    # Get nonce
    nonce = w3.client.get_nonce(MY)
    print(f"    Nonce: {nonce}")
    
    # Send EIP-1559 transaction
    print(f"\n[2] Sending EIP-1559 transaction...")
    
    # Use EIP-1559 parameters
    max_priority_fee = 1
    max_fee_per_gas = 2
    
    try:
        tx_hash = _eth_sign_and_send(
            w3.client,
            KEY,
            bytes.fromhex(recipient),
            transfer_amount,
            b'',  # No data for simple transfer
            nonce,
            gas_limit=21000,
            use_eip1559=True,
            max_priority_fee_per_gas=max_priority_fee,
            max_fee_per_gas=max_fee_per_gas
        )
        print(f"    ✅ Transaction sent!")
        print(f"    TX Hash: {tx_hash}")
        
        # Wait for transaction to be mined
        print(f"\n[3] Waiting for transaction confirmation...")
        max_wait = 30
        for i in range(max_wait):
            time.sleep(2)
            balance_after = w3.client.get_balance(recipient)
            if balance_after >= balance_before + transfer_amount:
                print(f"    ✅ Transaction confirmed!")
                print(f"    Recipient balance after: {balance_after}")
                print(f"    Balance increase: {balance_after - balance_before}")
                return True
            print(f"    [{i*2}s] Waiting... (balance: {balance_after})")
        
        print(f"    ⚠️  Transaction not confirmed within {max_wait*2}s")
        return False
        
    except Exception as e:
        print(f"    ❌ Transaction failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_eip1559_contract_deploy(w3, MY, KEY):
    """
    Test EIP-1559 contract deployment
    """
    print("\n" + "=" * 70)
    print("TEST CASE 2: EIP-1559 Contract Deployment")
    print("=" * 70)
    
    print(f"\n[1] Compiling contract...")
    bytecode, abi = compile_and_link(TEST_CONTRACT_SOL, "EIP1559Test")
    print(f"    ✅ Contract compiled")
    print(f"    Bytecode length: {len(bytecode)} bytes")
    
    print(f"\n[2] Deploying contract with EIP-1559...")
    
    # Get nonce
    nonce = w3.client.get_nonce(MY)
    
    try:
        # Deploy using EIP-1559
        tx_hash = _eth_sign_and_send(
            w3.client,
            KEY,
            b'',  # Empty 'to' for contract creation
            0,    # No value
            bytes.fromhex(bytecode),
            nonce,
            gas_limit=5000000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        print(f"    ✅ Deployment transaction sent!")
        print(f"    TX Hash: {tx_hash}")
        
        # Calculate contract address (Ethereum CREATE formula)
        from seth_sdk import calc_create_address
        contract_addr = calc_create_address(MY, nonce)
        print(f"    Expected contract address: {contract_addr}")
        
        # Wait for deployment
        print(f"\n[3] Waiting for deployment confirmation...")
        time.sleep(10)
        
        # Verify contract exists
        code = w3.client.get_code(contract_addr)
        if code and code != "0x":
            print(f"    ✅ Contract deployed successfully!")
            print(f"    Contract address: {contract_addr}")
            print(f"    Code length: {len(code)} bytes")
            return contract_addr, abi
        else:
            print(f"    ⚠️  Contract code not found")
            return None, None
            
    except Exception as e:
        print(f"    ❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def test_eip1559_contract_call(w3, MY, KEY, contract_addr, abi):
    """
    Test EIP-1559 contract function call
    """
    print("\n" + "=" * 70)
    print("TEST CASE 3: EIP-1559 Contract Function Call")
    print("=" * 70)
    
    if not contract_addr or not abi:
        print("    ⚠️  Skipping: No contract deployed")
        return False
    
    print(f"\n[1] Creating contract instance...")
    contract = w3.seth.contract(address=contract_addr, abi=abi, sender_address=MY)
    print(f"    ✅ Contract instance created")
    
    # Read initial value
    print(f"\n[2] Reading initial value...")
    try:
        result = contract.functions.getValue().call()
        initial_value = result[0] if isinstance(result, (list, tuple)) else result
        print(f"    Initial value: {initial_value}")
    except Exception as e:
        print(f"    ⚠️  Could not read initial value: {e}")
        initial_value = 0
    
    # Set new value using EIP-1559
    print(f"\n[3] Setting value to 12345 using EIP-1559...")
    new_value = 12345
    
    # Get nonce
    nonce = w3.client.get_nonce(MY)
    
    # Encode function call
    from eth_abi import encode
    function_selector = bytes.fromhex("55241077")  # setValue(uint256) selector
    encoded_data = function_selector + encode(['uint256'], [new_value])
    
    try:
        tx_hash = _eth_sign_and_send(
            w3.client,
            KEY,
            bytes.fromhex(contract_addr),
            0,  # No value
            encoded_data,
            nonce,
            gas_limit=500000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        print(f"    ✅ Transaction sent!")
        print(f"    TX Hash: {tx_hash}")
        
        # Wait for transaction
        print(f"\n[4] Waiting for transaction confirmation...")
        time.sleep(10)
        
        # Read new value
        print(f"\n[5] Reading new value...")
        result = contract.functions.getValue().call()
        final_value = result[0] if isinstance(result, (list, tuple)) else result
        print(f"    Final value: {final_value}")
        
        if final_value == new_value:
            print(f"    ✅ Value updated successfully!")
            return True
        else:
            print(f"    ⚠️  Value mismatch: expected {new_value}, got {final_value}")
            return False
            
    except Exception as e:
        print(f"    ❌ Transaction failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """
    Main test function
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='EIP-1559 Transaction Test')
    parser.add_argument('--host', default='127.0.0.1', help='Seth node host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=23001, help='Seth node port (default: 23001)')
    parser.add_argument('--key', 
                        default='71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6',
                        help='Private key (hex, default: test key)')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("EIP-1559 Transaction Test Suite")
    print("=" * 70)
    print(f"Host: {args.host}:{args.port}")
    print(f"Private Key: {args.key[:8]}...{args.key[-8:]}")
    
    # Initialize client
    w3 = SethWeb3Mock(args.host, args.port)
    MY = w3.client.get_address(args.key)
    print(f"Sender Address: {MY}")
    
    # Get initial balance
    balance = w3.client.get_balance(MY)
    print(f"Sender Balance: {balance}")
    
    if balance < 10000000:
        print("\n⚠️  WARNING: Low balance, tests may fail!")
    
    # Run tests
    results = []
    
    # Test 1: EIP-1559 Transfer
    results.append(("EIP-1559 Transfer", test_eip1559_transfer(w3, MY, args.key)))
    
    # Test 2: EIP-1559 Contract Deploy
    contract_addr, abi = test_eip1559_contract_deploy(w3, MY, args.key)
    results.append(("EIP-1559 Contract Deploy", contract_addr is not None))
    
    # Test 3: EIP-1559 Contract Call
    if contract_addr:
        results.append(("EIP-1559 Contract Call", test_eip1559_contract_call(w3, MY, args.key, contract_addr, abi)))
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:.<50} {status}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
