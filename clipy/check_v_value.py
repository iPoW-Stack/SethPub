#!/usr/bin/env python3
"""Check the actual v value in the signed transaction"""

# From the test output
raw_tx_hex = "02f86984c7facf958001028252089442a7ec028bb9073af5d2989b4d5df9285f82a6e6830f424080c080a093c1f4a47176ceca5da0a1eebc73e247c285fbfa63d52ef2112ac755577fb54fa05e164cf93691b387ee622c3f73e1ec8b121807ba8f3beba46bbd8db1760b5900"

raw_bytes = bytes.fromhex(raw_tx_hex)

print("Analyzing transaction...")
print(f"Full hex: {raw_tx_hex}")
print()

# Find the v, r, s values
# They are at the end: ...accessList, v, r, s
# accessList is 0xc0 (empty list)
# v is next
# r is 0xa0 + 32 bytes
# s is 0xa0 + 32 bytes

# Search for the pattern: 0xc0 0x80 (accessList empty) followed by v
for i in range(len(raw_bytes) - 70):
    if raw_bytes[i] == 0xc0 and raw_bytes[i+1] == 0x80:
        # Found accessList = 0xc0 0x80 (empty list with one empty element)
        # Actually, empty list is just 0xc0
        pass
    if raw_bytes[i] == 0x80 and raw_bytes[i+1] == 0xc0:
        # data=0x80 (empty), accessList=0xc0 (empty list)
        v_idx = i + 2
        v_byte = raw_bytes[v_idx]
        print(f"Found at index {v_idx}:")
        print(f"  data: 0x{raw_bytes[i]:02x}")
        print(f"  accessList: 0x{raw_bytes[i+1]:02x}")
        print(f"  v: 0x{v_byte:02x} (decimal: {v_byte})")
        
        # Check if next is r (should be 0xa0 for 32-byte string)
        r_idx = v_idx + 1
        if raw_bytes[r_idx] == 0xa0:
            r_bytes = raw_bytes[r_idx+1:r_idx+33]
            print(f"  r: {r_bytes.hex()}")
            
            s_idx = r_idx + 33
            if raw_bytes[s_idx] == 0xa0:
                s_bytes = raw_bytes[s_idx+1:s_idx+33]
                print(f"  s: {s_bytes.hex()}")
                print()
                print(f"✓ Found complete signature: v={v_byte}, r={r_bytes.hex()[:16]}..., s={s_bytes.hex()[:16]}...")
                break

print()
print("Now let's verify recovery with both v=0 and v=1:")
print("-" * 70)

from eth_keys import keys
from Crypto.Hash import keccak

# Build signing hash
def rlp_encode_uint(v: int) -> bytes:
    if v == 0:
        return b'\x80'
    be = []
    while v > 0:
        be.append(v & 0xff)
        v >>= 8
    be.reverse()
    be_bytes = bytes(be)
    if len(be_bytes) == 1 and be_bytes[0] < 0x80:
        return be_bytes
    return bytes([0x80 + len(be_bytes)]) + be_bytes

def rlp_encode_bytes(b: bytes) -> bytes:
    if len(b) == 0:
        return b'\x80'
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    len_be = []
    sz = len(b)
    while sz > 0:
        len_be.append(sz & 0xff)
        sz >>= 8
    len_be.reverse()
    len_bytes = bytes(len_be)
    return bytes([0xb7 + len(len_bytes)]) + len_bytes + b

def rlp_list(payload: bytes) -> bytes:
    if len(payload) <= 55:
        return bytes([0xc0 + len(payload)]) + payload
    len_be = []
    sz = len(payload)
    while sz > 0:
        len_be.append(sz & 0xff)
        sz >>= 8
    len_be.reverse()
    len_bytes = bytes(len_be)
    return bytes([0xf7 + len(len_bytes)]) + len_bytes + payload

# Transaction parameters
chain_id = 3355103125
nonce = 0
max_priority = 1
max_fee = 2
gas_limit = 21000
to = bytes.fromhex("42a7ec028bb9073af5d2989b4d5df9285f82a6e6")
value = 1000000
data = b''

payload = b''
payload += rlp_encode_uint(chain_id)
payload += rlp_encode_uint(nonce)
payload += rlp_encode_uint(max_priority)
payload += rlp_encode_uint(max_fee)
payload += rlp_encode_uint(gas_limit)
payload += rlp_encode_bytes(to)
payload += rlp_encode_uint(value)
payload += rlp_encode_bytes(data)
payload += rlp_encode_bytes(b'')  # accessList

signing_rlp = rlp_list(payload)
type_and_rlp = b'\x02' + signing_rlp
signing_hash = keccak.new(digest_bits=256).update(type_and_rlp).digest()

print(f"Signing hash: {signing_hash.hex()}")
print()

# Get r, s from transaction
r_bytes = bytes.fromhex("93c1f4a47176ceca5da0a1eebc73e247c285fbfa63d52ef2112ac755577fb54f")
s_bytes = bytes.fromhex("5e164cf93691b387ee622c3f73e1ec8b121807ba8f3beba46bbd8db1760b5900")

expected_addr = "b43b7ada2c7b17e0008501ded58d388a1bd72257"

for test_v in [0, 1]:
    try:
        sig_bytes = r_bytes + s_bytes + bytes([test_v])
        signature = keys.Signature(signature_bytes=sig_bytes)
        pubkey = signature.recover_public_key_from_msg_hash(signing_hash)
        pubkey_bytes = pubkey.to_bytes()  # 64 bytes, no prefix
        address = pubkey.to_checksum_address()
        
        match = "✓ MATCH!" if address.lower().replace('0x', '') == expected_addr else "✗ wrong"
        print(f"v={test_v}: pubkey={pubkey_bytes.hex()[:32]}... addr={address} {match}")
    except Exception as e:
        print(f"v={test_v}: Failed - {e}")

print()
print("="*70)
print("Conclusion:")
print("="*70)
print("The correct v value should be the one that recovers to:")
print(f"  {expected_addr}")
print()
