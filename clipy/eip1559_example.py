#!/usr/bin/env python3
"""
EIP-1559 Transaction Simple Example

This is a minimal example showing how to send EIP-1559 transactions.
"""

from seth_sdk import SethWeb3Mock, _eth_sign_and_send

# Configuration
HOST = "127.0.0.1"
PORT = 23001
PRIVATE_KEY = "7c5b4ec643cfe561eba395569a41c04697920688e2daa4535e30969ffc8a4f66"

def main():
    print("=" * 60)
    print("EIP-1559 Transaction Example")
    print("=" * 60)
    
    # Initialize client
    w3 = SethWeb3Mock(HOST, PORT)
    sender = w3.client.get_address(PRIVATE_KEY)
    
    print(f"\nSender: {sender}")
    print(f"Balance: {w3.client.get_balance(sender)}")
    
    # Recipient address (example)
    recipient = "0000000000000000000000000000000000000001"
    
    # Get nonce
    nonce = w3.client.get_nonce(sender)
    print(f"Nonce: {nonce}")
    
    # Send EIP-1559 transaction
    print(f"\nSending EIP-1559 transaction...")
    print(f"  To: {recipient}")
    print(f"  Value: 1000000")
    print(f"  Max Fee Per Gas: 2")
    print(f"  Max Priority Fee Per Gas: 1")
    
    try:
        tx_hash = _eth_sign_and_send(
            w3.client,
            PRIVATE_KEY,
            bytes.fromhex(recipient),
            value=1000000,
            data=b'',
            nonce=nonce,
            gas_limit=21000,
            use_eip1559=True,
            max_priority_fee_per_gas=1,
            max_fee_per_gas=2
        )
        
        print(f"\n✅ Transaction sent successfully!")
        print(f"TX Hash: {tx_hash}")
        
        # Wait and check balance
        import time
        print(f"\nWaiting 10 seconds for confirmation...")
        time.sleep(10)
        
        new_balance = w3.client.get_balance(recipient)
        print(f"Recipient balance: {new_balance}")
        
    except Exception as e:
        print(f"\n❌ Transaction failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
