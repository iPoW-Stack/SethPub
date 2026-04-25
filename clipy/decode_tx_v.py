#!/usr/bin/env python3
"""Decode the v value from the EIP-1559 transaction"""

raw_tx_hex = "02f86984c7facf958001028252089442a7ec028bb9073af5d2989b4d5df9285f82a6e6830f424080c080a093c1f4a47176ceca5da0a1eebc73e247c285fbfa63d52ef2112ac755577fb54fa05e164cf93691b387ee622c3f73e1ec8b121807ba8f3beba46bbd8db1760b5900"

raw_bytes = bytes.fromhex(raw_tx_hex)

print("Transaction breakdown:")
print(f"Type byte: 0x{raw_bytes[0]:02x}")
print(f"RLP list header: 0x{raw_bytes[1]:02x}")

# Skip type (1 byte) and list header (2 bytes for 0xf869)
idx = 3

fields = ["chainId", "nonce", "maxPriorityFee", "maxFee", "gasLimit", "to", "value", "data", "accessList", "v", "r", "s"]

for field in fields:
    if idx >= len(raw_bytes):
        break
    
    byte = raw_bytes[idx]
    if byte < 0x80:
        print(f"{field}: 0x{byte:02x} (value={byte})")
        idx += 1
    elif byte <= 0xb7:
        length = byte - 0x80
        if length == 0:
            print(f"{field}: 0x80 (empty)")
            idx += 1
        else:
            value_bytes = raw_bytes[idx+1:idx+1+length]
            value_hex = value_bytes.hex()
            if length <= 8:
                value_int = int.from_bytes(value_bytes, 'big')
                print(f"{field}: 0x{byte:02x} {value_hex} (length={length}, value={value_int})")
            else:
                print(f"{field}: 0x{byte:02x} {value_hex} (length={length})")
            idx += 1 + length
    elif byte <= 0xbf:
        hlen = byte - 0xb7
        length = int.from_bytes(raw_bytes[idx+1:idx+1+hlen], 'big')
        value_bytes = raw_bytes[idx+1+hlen:idx+1+hlen+length]
        print(f"{field}: 0x{byte:02x} ... (long string, length={length})")
        idx += 1 + hlen + length
    elif byte <= 0xf7:
        length = byte - 0xc0
        print(f"{field}: 0x{byte:02x} (list, length={length})")
        idx += 1 + length
    else:
        hlen = byte - 0xf7
        length = int.from_bytes(raw_bytes[idx+1:idx+1+hlen], 'big')
        print(f"{field}: 0x{byte:02x} (long list, length={length})")
        idx += 1 + hlen + length

print("\n" + "="*70)
print("Key finding:")
print("="*70)

# The v value should be at a specific position
# Let's find it by looking for the pattern: accessList (0x80), v, r (0xa0 + 32 bytes), s (0xa0 + 32 bytes)
# Find the last 0x80 before two 0xa0 entries
for i in range(len(raw_bytes) - 66):
    if raw_bytes[i] == 0x80 and raw_bytes[i+1] == 0xc0 and raw_bytes[i+2] == 0x80:
        # Found: data=0x80, accessList=0xc0 0x80, v=next
        v_idx = i + 3
        v_value = raw_bytes[v_idx]
        print(f"Found v at index {v_idx}: 0x{v_value:02x} (value={v_value})")
        
        r_idx = v_idx + 1
        if raw_bytes[r_idx] == 0xa0:
            r_bytes = raw_bytes[r_idx+1:r_idx+33]
            print(f"r: {r_bytes.hex()}")
            
            s_idx = r_idx + 33
            if raw_bytes[s_idx] == 0xa0:
                s_bytes = raw_bytes[s_idx+1:s_idx+33]
                print(f"s: {s_bytes.hex()}")
        break
