#!/usr/bin/env python3
"""Verify the signature components (r, s, v) from the EIP-1559 transaction"""

from eth_account import Account
from Crypto.Hash import keccak
import rlp

# The raw transaction from the test
raw_tx_hex = "02f86984c7facf958001028252089442a7ec028bb9073af5d2989b4d5df9285f82a6e6830f424080c080a093c1f4a47176ceca5da0a1eebc73e247c285fbfa63d52ef2112ac755577fb54fa05e164cf93691b387ee622c3f73e1ec8b121807ba8f3beba46bbd8db1760b5900"
raw_tx_bytes = bytes.fromhex(raw_tx_hex)

print("="*70)
print("EIP-1559 Transaction Signature Analysis")
print("="*70)
print()

# Decode the transaction manually
print("1. Raw Transaction Breakdown:")
print("-"*70)
print(f"Full hex: {raw_tx_hex}")
print(f"Length: {len(raw_tx_bytes)} bytes")
print()

# Parse the signature components from the end
# EIP-1559 format: 0x02 || RLP([...fields..., v, r, s])
# r and s are 32 bytes each, v is variable (usually 1 byte for EIP-1559)

# Find r and s (last 64 bytes of the RLP payload)
# The transaction ends with: ...v, r(0xa0 + 32 bytes), s(0xa0 + 32 bytes)

# Look for the pattern: 0xa0 (32-byte string) twice at the end
idx = len(raw_tx_bytes) - 1
s_start = len(raw_tx_bytes) - 32
r_start = s_start - 1 - 32  # -1 for the 0xa0 prefix

# Actually, let's parse properly
# Skip type byte and RLP list header
p = 1  # Skip 0x02
if raw_tx_bytes[p] >= 0xf8:
    hdr_len = 1 + (raw_tx_bytes[p] - 0xf7)
    p += hdr_len
else:
    p += 1

# Now parse fields
def parse_rlp_item(data, pos):
    """Parse one RLP item and return (value, new_pos)"""
    if data[pos] < 0x80:
        return bytes([data[pos]]), pos + 1
    elif data[pos] <= 0xb7:
        length = data[pos] - 0x80
        if length == 0:
            return b'', pos + 1
        return data[pos+1:pos+1+length], pos + 1 + length
    elif data[pos] <= 0xbf:
        hlen = data[pos] - 0xb7
        length = int.from_bytes(data[pos+1:pos+1+hlen], 'big')
        return data[pos+1+hlen:pos+1+hlen+length], pos + 1 + hlen + length
    elif data[pos] <= 0xf7:
        length = data[pos] - 0xc0
        return data[pos+1:pos+1+length], pos + 1 + length
    else:
        hlen = data[pos] - 0xf7
        length = int.from_bytes(data[pos+1:pos+1+hlen], 'big')
        return data[pos+1+hlen:pos+1+hlen+length], pos + 1 + hlen + length

fields = []
field_names = ["chainId", "nonce", "maxPriorityFee", "maxFee", "gasLimit", "to", "value", "data", "accessList", "v", "r", "s"]

for name in field_names:
    value, p = parse_rlp_item(raw_tx_bytes, p)
    fields.append((name, value))
    if name in ["v", "r", "s"]:
        if len(value) <= 8:
            print(f"{name}: {value.hex()} (int: {int.from_bytes(value, 'big') if value else 0})")
        else:
            print(f"{name}: {value.hex()}")

print()
print("2. Signature Components:")
print("-"*70)

v_value = fields[9][1]  # v
r_value = fields[10][1]  # r
s_value = fields[11][1]  # s

v_int = int.from_bytes(v_value, 'big') if v_value else 0
print(f"v = {v_int} (0x{v_int:02x})")
print(f"r = {r_value.hex()}")
print(f"s = {s_value.hex()}")
print()

# Verify with eth_account
print("3. Verify with eth_account:")
print("-"*70)
recovered = Account.recover_transaction(raw_tx_bytes)
print(f"Recovered address: {recovered}")
print()

# Now let's manually recover using the signing hash
print("4. Manual Recovery:")
print("-"*70)

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

# Extract transaction fields
chain_id = int.from_bytes(fields[0][1], 'big')
nonce = int.from_bytes(fields[1][1], 'big') if fields[1][1] else 0
max_priority = int.from_bytes(fields[2][1], 'big') if fields[2][1] else 0
max_fee = int.from_bytes(fields[3][1], 'big') if fields[3][1] else 0
gas_limit = int.from_bytes(fields[4][1], 'big')
to = fields[5][1]
value = int.from_bytes(fields[6][1], 'big')
data = fields[7][1]
access_list = fields[8][1]

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

# Try to recover with different v values
print("5. Test Recovery with Different v Values:")
print("-"*70)

from eth_keys import keys
from eth_utils import to_checksum_address

for test_v in [0, 1, 27, 28]:
    try:
        # Build signature: r + s + v
        sig_bytes = r_value + s_value + bytes([test_v])
        
        # Try to recover
        signature = keys.Signature(signature_bytes=sig_bytes)
        pubkey = signature.recover_public_key_from_msg_hash(signing_hash)
        address = pubkey.to_checksum_address()
        
        marker = " ← MATCH!" if address.lower() == recovered.lower() else ""
        print(f"v={test_v:2d}: {address}{marker}")
    except Exception as e:
        print(f"v={test_v:2d}: Failed - {e}")

print()
print("="*70)
print("Summary:")
print("="*70)
print(f"Transaction v value: {v_int}")
print(f"Expected address: {recovered}")
print(f"C++ should use v={v_int} for recovery")
print()
