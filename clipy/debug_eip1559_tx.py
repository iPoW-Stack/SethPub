#!/usr/bin/env python3
"""
Debug EIP-1559 transaction encoding
"""

from eth_account import Account
from eth_utils import to_checksum_address

# Test parameters
pk_hex = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
to = bytes.fromhex("0000000000000000000000000000000000000001")
value = 1000000
nonce = 8
gas_limit = 21000
max_priority_fee = 1
max_fee = 2
chain_id = 3355103125

# Build EIP-1559 transaction
tx = {
    'type': 2,
    'chainId': chain_id,
    'nonce': nonce,
    'maxPriorityFeePerGas': max_priority_fee,
    'maxFeePerGas': max_fee,
    'gas': gas_limit,
    'to': to_checksum_address('0x' + to.hex()),
    'value': value,
    'data': b'',
    'accessList': [],
}

print("Transaction dict:")
for k, v in tx.items():
    print(f"  {k}: {v}")

# Sign
signed = Account.sign_transaction(tx, '0x' + pk_hex)
raw_tx_bytes = signed.rawTransaction
raw_tx_hex = raw_tx_bytes.hex()

print(f"\nRaw transaction:")
print(f"  Length: {len(raw_tx_bytes)} bytes")
print(f"  Hex: {raw_tx_hex}")

# Decode structure
print(f"\nStructure analysis:")
print(f"  Byte 0 (type): 0x{raw_tx_bytes[0]:02x} (should be 0x02)")

if raw_tx_bytes[0] == 0x02:
    print(f"  ✅ EIP-1559 type byte correct")
    
    # RLP list header
    rlp_start = 1
    print(f"  Byte 1 (RLP list header): 0x{raw_tx_bytes[rlp_start]:02x}")
    
    if raw_tx_bytes[rlp_start] >= 0xf8:
        # Long list
        len_of_len = raw_tx_bytes[rlp_start] - 0xf7
        print(f"    Long list format, length-of-length: {len_of_len}")
        list_len = 0
        for i in range(len_of_len):
            list_len = (list_len << 8) | raw_tx_bytes[rlp_start + 1 + i]
        print(f"    List payload length: {list_len}")
        data_start = rlp_start + 1 + len_of_len
    elif raw_tx_bytes[rlp_start] >= 0xc0:
        # Short list
        list_len = raw_tx_bytes[rlp_start] - 0xc0
        print(f"    Short list format, payload length: {list_len}")
        data_start = rlp_start + 1
    else:
        print(f"    ❌ Invalid RLP list header")
        data_start = None
    
    if data_start:
        print(f"  Data starts at byte {data_start}")
        print(f"  First 20 bytes of data: {raw_tx_bytes[data_start:data_start+20].hex()}")
        
        # Try to decode fields manually
        print(f"\n  Attempting to decode fields:")
        p = data_start
        field_names = ['chainId', 'nonce', 'maxPriorityFeePerGas', 'maxFeePerGas', 
                       'gasLimit', 'to', 'value', 'data', 'accessList', 'v', 'r', 's']
        
        for field_name in field_names:
            if p >= len(raw_tx_bytes):
                print(f"    {field_name}: ❌ Out of bounds")
                break
            
            byte_val = raw_tx_bytes[p]
            if byte_val <= 0x7f:
                # Single byte
                print(f"    {field_name}: single byte 0x{byte_val:02x}")
                p += 1
            elif byte_val == 0x80:
                # Empty string
                print(f"    {field_name}: empty")
                p += 1
            elif byte_val <= 0xb7:
                # Short string
                item_len = byte_val - 0x80
                if p + 1 + item_len <= len(raw_tx_bytes):
                    item_data = raw_tx_bytes[p+1:p+1+item_len]
                    print(f"    {field_name}: {item_len} bytes = {item_data.hex()}")
                    p += 1 + item_len
                else:
                    print(f"    {field_name}: ❌ Short string out of bounds")
                    break
            elif byte_val <= 0xbf:
                # Long string
                len_of_len = byte_val - 0xb7
                if p + 1 + len_of_len <= len(raw_tx_bytes):
                    item_len = 0
                    for i in range(len_of_len):
                        item_len = (item_len << 8) | raw_tx_bytes[p + 1 + i]
                    if p + 1 + len_of_len + item_len <= len(raw_tx_bytes):
                        item_data = raw_tx_bytes[p+1+len_of_len:p+1+len_of_len+item_len]
                        print(f"    {field_name}: {item_len} bytes (long) = {item_data.hex()[:40]}...")
                        p += 1 + len_of_len + item_len
                    else:
                        print(f"    {field_name}: ❌ Long string data out of bounds")
                        break
                else:
                    print(f"    {field_name}: ❌ Long string length out of bounds")
                    break
            elif byte_val >= 0xc0:
                # List (for accessList)
                if byte_val <= 0xf7:
                    list_len = byte_val - 0xc0
                    print(f"    {field_name}: list of {list_len} bytes")
                    p += 1 + list_len
                else:
                    len_of_len = byte_val - 0xf7
                    if p + 1 + len_of_len <= len(raw_tx_bytes):
                        list_len = 0
                        for i in range(len_of_len):
                            list_len = (list_len << 8) | raw_tx_bytes[p + 1 + i]
                        print(f"    {field_name}: long list of {list_len} bytes")
                        p += 1 + len_of_len + list_len
                    else:
                        print(f"    {field_name}: ❌ Long list out of bounds")
                        break

print("\n" + "="*60)
print("Debug complete")
