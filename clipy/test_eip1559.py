#!/usr/bin/env python3
"""
EIP-1559 Transaction Test for Seth Blockchain
"""

import sys
import time
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seth3 import SethWeb3Mock, _eth_sign_and_send


def wait_nonce(w3, addr, expected, timeout=60):
    """Wait until nonce reaches expected value"""
    for i in range(timeout // 2):
        n = w3.client.get_nonce(addr)
        if n >= expected:
            return n
        time.sleep(2)
    return w3.client.get_nonce(addr)


def test_eip1559_transfer(w3, MY, KEY):
    """Test EIP-1559 native token transfer"""
    print("\n" + "=" * 70)
    print("TEST CASE 1: EIP-1559 Native Token Transfer")
    print("=" * 70)

    recipient = "1234567890123456789012345678901234567890"
    transfer_amount = 1000000

    # Query current nonce
    nonce = w3.client.get_nonce(MY)
    tx_nonce = nonce + 1  # Seth expects nonce = current + 1

    print(f"  From:   {MY}")
    print(f"  To:     {recipient}")
    print(f"  Amount: {transfer_amount}")
    print(f"  Nonce:  {tx_nonce} (current={nonce})")

    sender_balance_before = w3.client.get_balance(MY)
    print(f"  Sender balance before: {sender_balance_before}")

    try:
        tx_hash = _eth_sign_and_send(
            w3.client, KEY,
            bytes.fromhex(recipient),
            transfer_amount,
            b'',
            tx_nonce,
            gas_limit=21000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        print(f"  ✅ TX sent: {tx_hash}")
    except Exception as e:
        print(f"  ❌ Send failed: {e}")
        import traceback; traceback.print_exc()
        return False

    # Wait for nonce to increase
    print("  Waiting for confirmation...", end='', flush=True)
    final_nonce = wait_nonce(w3, MY, tx_nonce, timeout=60)
    if final_nonce >= tx_nonce:
        print(f" ✅ confirmed (nonce={final_nonce})")
        sender_balance_after = w3.client.get_balance(MY)
        print(f"  Sender balance after: {sender_balance_after}")
        print(f"  Sender balance change: -{sender_balance_before - sender_balance_after}")
        return True
    else:
        print(f" ❌ timeout (nonce={final_nonce})")
        return False


def test_eip1559_transfer_2(w3, MY, KEY):
    """Test second EIP-1559 transfer to verify sequential nonce works"""
    print("\n" + "=" * 70)
    print("TEST CASE 2: EIP-1559 Second Transfer (sequential nonce)")
    print("=" * 70)

    recipient = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
    transfer_amount = 500000

    nonce = w3.client.get_nonce(MY)
    tx_nonce = nonce + 1

    print(f"  From:   {MY}")
    print(f"  To:     {recipient}")
    print(f"  Amount: {transfer_amount}")
    print(f"  Nonce:  {tx_nonce} (current={nonce})")

    try:
        tx_hash = _eth_sign_and_send(
            w3.client, KEY,
            bytes.fromhex(recipient),
            transfer_amount,
            b'',
            tx_nonce,
            gas_limit=21000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        print(f"  ✅ TX sent: {tx_hash}")
    except Exception as e:
        print(f"  ❌ Send failed: {e}")
        import traceback; traceback.print_exc()
        return False

    print("  Waiting for confirmation...", end='', flush=True)
    final_nonce = wait_nonce(w3, MY, tx_nonce, timeout=60)
    if final_nonce >= tx_nonce:
        print(f" ✅ confirmed (nonce={final_nonce})")
        return True
    else:
        print(f" ❌ timeout (nonce={final_nonce})")
        return False


def test_eip1559_contract_deploy(w3, MY, KEY):
    """Test EIP-1559 contract deployment"""
    print("\n" + "=" * 70)
    print("TEST CASE 3: EIP-1559 Contract Deployment")
    print("=" * 70)

    # Minimal contract bytecode: stores a value
    # contract Store { uint256 public val; function set(uint256 v) public { val = v; } }
    # Using pre-compiled bytecode to avoid solc dependency
    bytecode = (
        "6080604052348015600e575f5ffd5b5060"
        "c680601a5f395ff3fe6080604052348015"
        "600e575f5ffd5b50600436106030575f35"
        "60e01c806360fe47b11460345780636d4c"
        "e63c14604c575b5f5ffd5b604a60048036"
        "03810190604691906078565b605e565b00"
        "5b60526067565b604051605d9190608f56"
        "5b60405180910390f35b805f8190555050"
        "565b5f5490565b5f819050919050565b60"
        "898160700190565b82525050565b5f6020"
        "820190506082602083018460810190565b"
        "9291505056fea164736f6c634300081e00"
        "0a"
    )

    nonce = w3.client.get_nonce(MY)
    tx_nonce = nonce + 1

    print(f"  Deploying contract with EIP-1559...")
    print(f"  Nonce: {tx_nonce} (current={nonce})")
    print(f"  Bytecode length: {len(bytecode)//2} bytes")

    try:
        tx_hash = _eth_sign_and_send(
            w3.client, KEY,
            b'',  # Empty 'to' for contract creation
            0,
            bytes.fromhex(bytecode),
            tx_nonce,
            gas_limit=5000000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        print(f"  ✅ Deploy TX sent: {tx_hash}")
    except Exception as e:
        print(f"  ❌ Deploy failed: {e}")
        import traceback; traceback.print_exc()
        return False

    print("  Waiting for confirmation...", end='', flush=True)
    final_nonce = wait_nonce(w3, MY, tx_nonce, timeout=60)
    if final_nonce >= tx_nonce:
        print(f" ✅ confirmed (nonce={final_nonce})")
        return True
    else:
        print(f" ❌ timeout (nonce={final_nonce})")
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='EIP-1559 Transaction Test')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=23001)
    parser.add_argument('--key',
                        default='71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6')
    args = parser.parse_args()

    print("=" * 70)
    print("EIP-1559 Transaction Test Suite")
    print("=" * 70)
    print(f"Host: {args.host}:{args.port}")
    print(f"Private Key: {args.key[:8]}...{args.key[-8:]}")

    w3 = SethWeb3Mock(args.host, args.port)
    MY = w3.client.get_address(args.key)
    print(f"Sender Address: {MY}")

    balance = w3.client.get_balance(MY)
    print(f"Sender Balance: {balance}")

    nonce = w3.client.get_nonce(MY)
    print(f"Current Nonce: {nonce}")

    results = []

    # Test 1: Transfer
    results.append(("EIP-1559 Transfer #1", test_eip1559_transfer(w3, MY, args.key)))

    # Test 2: Second transfer (sequential nonce)
    results.append(("EIP-1559 Transfer #2", test_eip1559_transfer_2(w3, MY, args.key)))

    # Test 3: Contract deploy
    results.append(("EIP-1559 Contract Deploy", test_eip1559_contract_deploy(w3, MY, args.key)))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    for name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {name:.<50} {status}")

    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\n  Total: {passed}/{total} tests passed")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
