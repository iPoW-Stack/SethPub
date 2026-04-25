#!/usr/bin/env python3
"""
Check transaction receipt for EIP-1559 transaction
"""

import sys
import time
import json
import requests
from seth3 import Seth3

# Configuration
HOST = "127.0.0.1"
PORT = 23001

# Transaction hash from the logs
TX_HASH = "0xf025a9a135c373c181a8c6d03f52fe9d54758be90f41381e17adc3556aa882fb"

def check_receipt(tx_hash):
    """Check transaction receipt using eth_getTransactionReceipt"""
    url = f"https://{HOST}:{PORT}/eth"
    
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash],
        "id": 1
    }
    
    try:
        response = requests.post(url, json=payload, verify=False, timeout=5)
        result = response.json()
        return result.get("result")
    except Exception as e:
        print(f"Error checking receipt: {e}")
        return None

def main():
    print("=" * 70)
    print("Transaction Receipt Checker")
    print("=" * 70)
    print(f"TX Hash: {TX_HASH}")
    print()
    
    # Check receipt multiple times
    for i in range(15):
        print(f"[{i*2}s] Checking receipt...")
        receipt = check_receipt(TX_HASH)
        
        if receipt is None:
            print("    Status: PENDING (not yet in block)")
        else:
            print("    Status: CONFIRMED")
            print(f"    Receipt: {json.dumps(receipt, indent=2)}")
            
            # Check status
            status = receipt.get("status")
            if status == "0x1":
                print("    ✅ Transaction SUCCESS")
            elif status == "0x0":
                print("    ❌ Transaction FAILED")
            else:
                print(f"    ⚠️  Unknown status: {status}")
            
            return 0
        
        if i < 14:
            time.sleep(2)
    
    print()
    print("⚠️  Transaction still pending after 30 seconds")
    print()
    print("Possible issues:")
    print("1. Single node not producing blocks automatically")
    print("2. Transaction pool not being processed")
    print("3. Need to trigger block production manually")
    
    return 1

if __name__ == "__main__":
    sys.exit(main())
