#!/usr/bin/env python3
"""
Verify signature recovery matches between Python and C++
"""

from eth_account import Account
from eth_account._utils.legacy_transactions import encode_transaction
from eth_keys import keys
from eth_utils import keccak, to_bytes, to_hex
import rlp

# Test data from logs
PRIVATE_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"
CHAIN_ID = 3355103125

# Transaction parameters
nonce = 0
max_priority_fee = 1
max_fee_per_gas = 2
gas_limit = 21000
to = bytes.fromhex("1234567890123456789012345678901234567890")
value = 1000000
data = b''

# Build EIP-1559 signing RLP
signing_rlp_list = [
    CHAIN_ID,
    nonce,
    max_priority_fee,
    max_fee_per_gas,
    gas_limit,
    to,
    value,
    data,
    []  # accessList
]

signing_rlp = b'\x02' + rlp.encode(signing_rlp_list)
signing_hash = keccak(signing_rlp)

print("=" * 70)
print("Signature Recovery Verification")
print("=" * 70)
print(f"Private Key: {PRIVATE_KEY}")
print(f"Chain ID: {CHAIN_ID}")
print()
print(f"Signing RLP: {to_hex(signing_rlp)}")
print(f"Signing Hash: {to_hex(signing_hash)}")
print()

# Sign with eth_account
account = Account.from_key(PRIVATE_KEY)
print(f"Expected Address: {account.address}")

# Sign the hash
signed = account.signHash(signing_hash)
print()
r_bytes = to_bytes(signed.r).rjust(32, b'\x00')
s_bytes = to_bytes(signed.s).rjust(32, b'\x00')
print(f"Signature r: {to_hex(r_bytes)}")
print(f"Signature s: {to_hex(s_bytes)}")
print(f"Signature v: {signed.v}")
print()

# Recover public key from signature
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend

backend = NativeECCBackend()
key_api = KeyAPI(backend)

# Try recovery with v as-is
try:
    signature_bytes = r_bytes + s_bytes + bytes([signed.v])
    recovered_key = key_api.ecdsa_recover(signing_hash, key_api.Signature(signature_bytes))
    recovered_address = recovered_key.to_checksum_address()
    recovered_pubkey = recovered_key.to_bytes()
    
    print(f"Recovered with v={signed.v}:")
    print(f"  Public Key: {to_hex(recovered_pubkey)}")
    print(f"  Address: {recovered_address}")
    print(f"  Match: {recovered_address.lower() == account.address.lower()}")
except Exception as e:
    print(f"Recovery with v={signed.v} failed: {e}")

print()

# Try recovery with v-27 (legacy format)
try:
    v_legacy = signed.v - 27 if signed.v >= 27 else signed.v
    signature_bytes = r_bytes + s_bytes + bytes([v_legacy])
    recovered_key = key_api.ecdsa_recover(signing_hash, key_api.Signature(signature_bytes))
    recovered_address = recovered_key.to_checksum_address()
    recovered_pubkey = recovered_key.to_bytes()
    
    print(f"Recovered with v={v_legacy} (v-27):")
    print(f"  Public Key: {to_hex(recovered_pubkey)}")
    print(f"  Address: {recovered_address}")
    print(f"  Match: {recovered_address.lower() == account.address.lower()}")
except Exception as e:
    print(f"Recovery with v={v_legacy} failed: {e}")

print()
print("=" * 70)
print("Expected by Python:")
print(f"  Public Key: {to_hex(account._key_obj.public_key.to_bytes())}")
print(f"  Address: {account.address}")
print("=" * 70)
