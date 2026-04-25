#!/usr/bin/env python3
"""
Send multiple transactions to trigger block production
"""

import sys
import time
from seth3 import Seth3

# Configuration
HOST = "127.0.0.1"
PORT = 23001
KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"

def send_simple_transaction(w3, key, recipient, amount, nonce):
    """Send a simple EIP-1559 transaction"""
    try:
        tx_hash = w3.client._eth_sign_and_send(
            key,
            bytes.fromhex(recipient),
            amount,
            b'',  # No data
            nonce,
            gas_limit=21000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        return tx_hash
    except Exception as e:
        print(f"Error sending transaction: {e}")
        return None

def main():
    print("=" * 70)
    print("Trigger Block Production by Sending Multiple Transactions")
    print("=" * 70)
    
    w3 = Seth3(HOST, PORT)
    
    # Get sender info
    sender = w3.client.get_address_from_key(KEY)
    print(f"Sender: {sender}")
    
    balance = w3.client.get_balance(sender)
    print(f"Balance: {balance}")
    
    nonce = w3.client.get_nonce(sender)
    print(f"Starting nonce: {nonce}")
    print()
    
    # Recipient address (different from sender)
    recipient = "8f00f5789549a311fd0a715367477a6b39fe2875"
    
    # Send 5 transactions
    print("Sending 5 transactions to trigger block production...")
    tx_hashes = []
    
    for i in range(5):
        print(f"\n[{i+1}/5] Sending transaction with nonce={nonce+i}...")
        tx_hash = send_simple_transaction(w3, KEY, recipient, 1000000, nonce + i)
        
        if tx_hash:
            print(f"  ✅ TX Hash: {tx_hash}")
            tx_hashes.append(tx_hash)
        else:
            print(f"  ❌ Failed to send transaction")
        
        # Small delay between transactions
        time.sleep(0.5)
    
    print()
    print("=" * 70)
    print(f"Sent {len(tx_hashes)} transactions")
    print()
    print("Now monitoring for block production...")
    print()
    
    # Monitor block number
    prev_block = w3.client.get_block_number()
    print(f"Current block: {prev_block}")
    
    for i in range(20):
        time.sleep(2)
        current_block = w3.client.get_block_number()
        
        if current_block > prev_block:
            print(f"[{i*2}s] Block: {current_block} (+{current_block - prev_block}) ✅ BLOCK PRODUCED!")
            prev_block = current_block
            
            # Check if recipient received funds
            recipient_balance = w3.client.get_balance(recipient)
            if recipient_balance > 0:
                print(f"  ✅ Recipient balance: {recipient_balance}")
                print()
                print("SUCCESS! Transactions were included in block!")
                return 0
        else:
            print(f"[{i*2}s] Block: {current_block} (no change)")
    
    print()
    print("⚠️  No new blocks produced after sending 5 transactions")
    print()
    print("This suggests the node may need:")
    print("1. More nodes for consensus (multi-node setup)")
    print("2. Special configuration for single-node block production")
    print("3. Manual trigger or different startup flags")
    
    return 1

if __name__ == "__main__":
    sys.exit(main())
