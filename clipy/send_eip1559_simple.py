#!/usr/bin/env python3
"""
Send EIP-1559 transactions sequentially, waiting for each to complete
"""

import sys
import time
from seth3 import Seth3

HOST = "127.0.0.1"
PORT = 23001
KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"

def wait_for_nonce_increase(w3, sender, expected_nonce, timeout=30):
    """Wait for nonce to increase to expected value"""
    print(f"  Waiting for nonce to reach {expected_nonce}...", end='', flush=True)
    start = time.time()
    while time.time() - start < timeout:
        current_nonce = w3.client.get_nonce(sender)
        if current_nonce >= expected_nonce:
            print(f" ✅ (nonce={current_nonce})")
            return True
        time.sleep(1)
        print('.', end='', flush=True)
    print(f" ❌ timeout")
    return False

def main():
    w3 = Seth3(HOST, PORT)
    
    sender = w3.client.get_address_from_key(KEY)
    print(f"Sender: {sender}")
    
    balance = w3.client.get_balance(sender)
    print(f"Balance: {balance}")
    
    recipient = "1234567890123456789012345678901234567890"
    amount = 1000000
    
    # Send 3 transactions sequentially
    for i in range(3):
        print(f"\n{'='*60}")
        print(f"Transaction {i+1}/3")
        print('='*60)
        
        # Get current nonce
        nonce = w3.client.get_nonce(sender)
        print(f"Current nonce: {nonce}")
        
        print(f"Sending EIP-1559 transaction:")
        print(f"  To: {recipient}")
        print(f"  Amount: {amount}")
        print(f"  Nonce: {nonce}")
        
        try:
            tx_hash = w3.client._eth_sign_and_send(
                KEY,
                bytes.fromhex(recipient),
                amount,
                b'',
                nonce,
                gas_limit=21000,
                use_eip1559=True,
                max_priority_fee_per_gas=1,
                max_fee_per_gas=2
            )
            print(f"  ✅ Transaction sent!")
            print(f"  TX Hash: {tx_hash}")
            
            # Wait for nonce to increase (transaction processed)
            if not wait_for_nonce_increase(w3, sender, nonce + 1):
                print(f"  ⚠️  Transaction may not have been processed")
                # Continue anyway
            
        except Exception as e:
            print(f"  ❌ Failed: {e}")
            import traceback
            traceback.print_exc()
            return 1
    
    print(f"\n{'='*60}")
    print("All transactions sent successfully!")
    print('='*60)
    
    # Check final balance
    final_balance = w3.client.get_balance(sender)
    print(f"Final balance: {final_balance}")
    print(f"Balance change: {balance - final_balance}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
