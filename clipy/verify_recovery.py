#!/usr/bin/env python3
"""Verify signature recovery with the actual values from the test"""

from eth_keys import keys
from Crypto.Hash import keccak

# From the C++ log
signing_hash_hex = "91f9a9007e7a64187cf599052b4d370efd636fa9e2028e9183ed7e6a1cf10d4d"
r_hex = "2d29566f32b18004a2f28380c0ad78fed8646cea1480cb432e379e08ee4f7cf6"
s_hex = "2f2e89570b2e825b1be0cbee87d050f35784d3d32a3e05841b24744511a2f45a"

signing_hash = bytes.fromhex(signing_hash_hex)
r = bytes.fromhex(r_hex)
s = bytes.fromhex(s_hex)

expected_pubkey = "5e3ae491ca10790f96913451a70f3d3e701d885218b6820ca1db188e369d617568198be22209764d7be62eaf9343c3fc3e2962c90f316896e11d70e942b7633a"
expected_addr = "b43b7ada2c7b17e0008501ded58d388a1bd72257"

print("="*70)
print("Signature Recovery Verification")
print("="*70)
print()
print(f"Signing hash: {signing_hash_hex}")
print(f"r: {r_hex}")
print(f"s: {s_hex}")
print()
print(f"Expected pubkey: {expected_pubkey}")
print(f"Expected address: {expected_addr}")
print()

# Try both v values
for v in [0, 1]:
    print(f"\nTrying v={v}:")
    print("-"*70)
    
    try:
        sig_bytes = r + s + bytes([v])
        signature = keys.Signature(signature_bytes=sig_bytes)
        pubkey = signature.recover_public_key_from_msg_hash(signing_hash)
        pubkey_bytes = pubkey.to_bytes()  # 64 bytes, no prefix
        address = pubkey.to_checksum_address().lower().replace('0x', '')
        
        pubkey_match = "✓ MATCH!" if pubkey_bytes.hex() == expected_pubkey else "✗ different"
        addr_match = "✓ MATCH!" if address == expected_addr else "✗ different"
        
        print(f"  Recovered pubkey: {pubkey_bytes.hex()}")
        print(f"  Pubkey match: {pubkey_match}")
        print(f"  Recovered address: {address}")
        print(f"  Address match: {addr_match}")
        
        # Also show what C++ recovered
        if v == 0:
            cpp_pubkey_v0 = "5aa445728fb752b8ba6cfcc2e3ba700d75aa71491246aec28c54d00ec8f3ead4c3ef516c0183d74fce48f906af712f535965541a1598997e3eba4ca0e395505e"
            print(f"  C++ recovered: {cpp_pubkey_v0}")
            print(f"  C++ matches Python: {'✓ YES' if cpp_pubkey_v0 == pubkey_bytes.hex() else '✗ NO'}")
        else:
            cpp_pubkey_v1 = "36633210039fce33ea25c8e792efcc92f54dee238916bb72e2217169adabbaa688463b5ba3d75d740bad17340091ab07e9f9949a3ac7f9ccee45d31e2ee99d40"
            print(f"  C++ recovered: {cpp_pubkey_v1}")
            print(f"  C++ matches Python: {'✓ YES' if cpp_pubkey_v1 == pubkey_bytes.hex() else '✗ NO'}")
            
    except Exception as e:
        print(f"  Failed: {e}")

print()
print("="*70)
print("Conclusion:")
print("="*70)

# Now let's verify with eth_account
from eth_account import Account

raw_tx_hex = "02f86984c7facf9580010282520894d1f642115dafe81fb241cb94f2bd32c224e760eb830f424080c001a02d29566f32b18004a2f28380c0ad78fed8646cea1480cb432e379e08ee4f7cf6a02f2e89570b2e825b1be0cbee87d050f35784d3d32a3e05841b24744511a2f45a"
raw_tx_bytes = bytes.fromhex(raw_tx_hex)

recovered_addr = Account.recover_transaction(raw_tx_bytes)
print(f"\neth_account recovered address: {recovered_addr}")
print(f"Expected address: 0x{expected_addr}")
print(f"Match: {'✓ YES' if recovered_addr.lower() == '0x' + expected_addr else '✗ NO'}")
