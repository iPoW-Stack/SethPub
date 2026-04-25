#!/usr/bin/env python3
"""
Compare EIP-1559 signing hash calculation between Python and expected C++ behavior.
This helps debug signature verification issues.
"""

from Crypto.Hash import keccak

def rlp_encode_uint(v: int) -> bytes:
    """RLP encode an unsigned integer."""
    if v == 0:
        return b'\x80'
    # Minimal big-endian representation
    be = []
    while v > 0:
        be.append(v & 0xff)
        v >>= 8
    be.reverse()
    be_bytes = bytes(be)
    # Single byte < 0x80 encodes as itself
    if len(be_bytes) == 1 and be_bytes[0] < 0x80:
        return be_bytes
    # Otherwise 0x80 + len prefix
    return bytes([0x80 + len(be_bytes)]) + be_bytes

def rlp_encode_bytes(b: bytes) -> bytes:
    """RLP encode a byte string."""
    if len(b) == 0:
        return b'\x80'
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    # Long string
    len_be = []
    sz = len(b)
    while sz > 0:
        len_be.append(sz & 0xff)
        sz >>= 8
    len_be.reverse()
    len_bytes = bytes(len_be)
    return bytes([0xb7 + len(len_bytes)]) + len_bytes + b

def rlp_list(payload: bytes) -> bytes:
    """RLP encode a list (payload is concatenated RLP items)."""
    if len(payload) <= 55:
        return bytes([0xc0 + len(payload)]) + payload
    # Long list
    len_be = []
    sz = len(payload)
    while sz > 0:
        len_be.append(sz & 0xff)
        sz >>= 8
    len_be.reverse()
    len_bytes = bytes(len_be)
    return bytes([0xf7 + len(len_bytes)]) + len_bytes + payload

def calculate_eip1559_signing_hash(
    chain_id: int,
    nonce: int,
    max_priority_fee: int,
    max_fee_per_gas: int,
    gas_limit: int,
    to: bytes,
    value: int,
    data: bytes
) -> tuple[bytes, bytes]:
    """
    Calculate EIP-1559 signing hash.
    Returns: (signing_rlp_with_prefix, signing_hash)
    """
    payload = b''
    payload += rlp_encode_uint(chain_id)
    payload += rlp_encode_uint(nonce)
    payload += rlp_encode_uint(max_priority_fee)
    payload += rlp_encode_uint(max_fee_per_gas)
    payload += rlp_encode_uint(gas_limit)
    payload += rlp_encode_bytes(to)
    payload += rlp_encode_uint(value)
    payload += rlp_encode_bytes(data)
    payload += rlp_encode_bytes(b'')  # accessList (empty)
    
    signing_rlp = rlp_list(payload)
    type_and_rlp = b'\x02' + signing_rlp
    signing_hash = keccak.new(digest_bits=256).update(type_and_rlp).digest()
    
    return type_and_rlp, signing_hash

def main():
    print("=" * 70)
    print("EIP-1559 Signing Hash Calculator")
    print("=" * 70)
    print()
    
    # Test Case 1: Simple transfer
    print("Test Case 1: Simple Transfer")
    print("-" * 70)
    chain_id = 3355103125  # 0xc7facf95
    nonce = 0
    max_priority_fee = 1
    max_fee_per_gas = 2
    gas_limit = 21000
    to = bytes.fromhex("6d99bdfd1bc33c1a682753dd38985d7548ac912a")
    value = 1000000
    data = b''
    
    signing_rlp, signing_hash = calculate_eip1559_signing_hash(
        chain_id, nonce, max_priority_fee, max_fee_per_gas,
        gas_limit, to, value, data
    )
    
    print(f"Chain ID: {chain_id} (0x{chain_id:x})")
    print(f"Nonce: {nonce}")
    print(f"Max Priority Fee: {max_priority_fee}")
    print(f"Max Fee Per Gas: {max_fee_per_gas}")
    print(f"Gas Limit: {gas_limit}")
    print(f"To: {to.hex()}")
    print(f"Value: {value}")
    print(f"Data: (empty)")
    print()
    print(f"Signing RLP (with 0x02 prefix): {signing_rlp.hex()}")
    print(f"Signing Hash: {signing_hash.hex()}")
    print()
    
    # Test Case 2: What if C++ uses same value for both fees (OLD BUG)
    print("Test Case 2: OLD BUG (using gas_price for both fees)")
    print("-" * 70)
    signing_rlp_bug, signing_hash_bug = calculate_eip1559_signing_hash(
        chain_id, nonce, 
        max_fee_per_gas,  # BUG: using max_fee_per_gas instead of max_priority_fee
        max_fee_per_gas,
        gas_limit, to, value, data
    )
    
    print(f"Max Priority Fee: {max_fee_per_gas} (WRONG! Should be {max_priority_fee})")
    print(f"Max Fee Per Gas: {max_fee_per_gas}")
    print()
    print(f"Signing RLP (with 0x02 prefix): {signing_rlp_bug.hex()}")
    print(f"Signing Hash: {signing_hash_bug.hex()}")
    print()
    
    if signing_hash == signing_hash_bug:
        print("⚠️  WARNING: Hashes are the same! This shouldn't happen.")
    else:
        print("✓ Hashes are different (as expected)")
        print(f"  Correct: {signing_hash.hex()}")
        print(f"  Buggy:   {signing_hash_bug.hex()}")
    print()
    
    # Decode the RLP to show structure
    print("RLP Structure Breakdown:")
    print("-" * 70)
    rlp_hex = signing_rlp.hex()
    print(f"Full: {rlp_hex}")
    print(f"  [0] Type byte: {rlp_hex[0:2]} (0x02 = EIP-1559)")
    print(f"  [1] List header: {rlp_hex[2:4]} (0x{int(rlp_hex[2:4], 16) - 0xc0:02x} = {int(rlp_hex[2:4], 16) - 0xc0} bytes)")
    
    # Parse fields
    idx = 4
    fields = [
        "chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas",
        "gasLimit", "to", "value", "data", "accessList"
    ]
    
    for field in fields:
        if idx >= len(rlp_hex):
            break
        byte = int(rlp_hex[idx:idx+2], 16)
        if byte < 0x80:
            # Single byte value
            print(f"  {field}: {rlp_hex[idx:idx+2]} (value={byte})")
            idx += 2
        elif byte <= 0xb7:
            # Short string
            length = byte - 0x80
            if length == 0:
                print(f"  {field}: {rlp_hex[idx:idx+2]} (empty)")
                idx += 2
            else:
                print(f"  {field}: {rlp_hex[idx:idx+2+length*2]} (length={length})")
                idx += 2 + length * 2
        elif byte <= 0xbf:
            # Long string
            hlen = byte - 0xb7
            length = int(rlp_hex[idx+2:idx+2+hlen*2], 16)
            print(f"  {field}: {rlp_hex[idx:idx+2+hlen*2+length*2]} (length={length})")
            idx += 2 + hlen * 2 + length * 2
        elif byte <= 0xf7:
            # Short list
            length = byte - 0xc0
            print(f"  {field}: {rlp_hex[idx:idx+2+length*2]} (list, length={length})")
            idx += 2 + length * 2
        else:
            # Long list
            hlen = byte - 0xf7
            length = int(rlp_hex[idx+2:idx+2+hlen*2], 16)
            print(f"  {field}: {rlp_hex[idx:idx+2+hlen*2+length*2]} (list, length={length})")
            idx += 2 + hlen * 2 + length * 2
    
    print()
    print("=" * 70)
    print("Instructions:")
    print("=" * 70)
    print("1. Compare the 'Signing Hash' above with your Python debug output")
    print("2. After recompiling C++, check server logs for the C++ signing hash")
    print("3. All three hashes should match:")
    print("   - This script")
    print("   - Python client debug output")
    print("   - C++ server log output")
    print()

if __name__ == "__main__":
    main()
