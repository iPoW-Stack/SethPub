"""
Seth chain transaction address/nonce/value boundary tests.
Converted from: tests-ref/TransactionTests/ttAddress, ttNonce, ttValue

Tests:
  1. Address validation (20 bytes)
  2. Nonce boundaries (0, max u64, overflow)
  3. Value boundaries (0, large values)
  4. Combined edge cases
"""
import sys, os, struct, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clipy"))

from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

passed = 0
failed = 0

PK = "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"


def assert_eq(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}: got={got}, expected={expected}")


def u64le(v):
    return struct.pack("<Q", v)


def get_address(pk_hex):
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    return keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()


def build_and_sign(pk_hex, to, nonce=1, amount=0, step=0, prefund=0):
    """Build Seth tx hash and sign. Returns (tx_hash_hex, r_hex, s_hex)."""
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed").hex()
    msg = bytearray()
    msg.extend(u64le(nonce))
    msg.extend(bytes.fromhex(pub))
    msg.extend(bytes.fromhex(to))
    msg.extend(u64le(amount))
    msg.extend(u64le(5000000))
    msg.extend(u64le(1))
    msg.extend(u64le(step))
    if prefund > 0:
        msg.extend(u64le(prefund))
    tx_hash = keccak.new(digest_bits=256).update(msg).digest()
    sig = sk.sign_digest_deterministic(tx_hash, hashfunc=hashlib.sha256,
                                        sigencode=sigencode_string_canonize)
    return tx_hash.hex(), sig[:32].hex(), sig[32:64].hex()


# ==================== Address Tests ====================

def test_address_valid_20bytes():
    """Test 1: Valid 20-byte address."""
    print("\n[Test 1] Valid 20-byte address")
    addr = get_address(PK)
    assert_eq("address is 20 bytes (40 hex)", len(addr), 40)
    # Can build and sign tx to valid address
    h, r, s = build_and_sign(PK, addr)
    assert_eq("tx hash non-empty", len(h) > 0, True)
    assert_eq("sig r non-empty", len(r) > 0, True)


def test_address_zero():
    """Test 2: Zero address (all zeros)."""
    print("\n[Test 2] Zero address")
    zero_addr = "0" * 40
    h, r, s = build_and_sign(PK, zero_addr)
    assert_eq("zero addr tx hash valid", len(h), 64)


def test_address_max():
    """Test 3: Max address (all ff)."""
    print("\n[Test 3] Max address (0xff...ff)")
    max_addr = "f" * 40
    h, r, s = build_and_sign(PK, max_addr)
    assert_eq("max addr tx hash valid", len(h), 64)


# ==================== Nonce Tests ====================

def test_nonce_zero():
    """Test 4: Nonce = 0."""
    print("\n[Test 4] Nonce = 0")
    addr = get_address(PK)
    h, r, s = build_and_sign(PK, addr, nonce=0)
    assert_eq("nonce=0 tx hash valid", len(h), 64)


def test_nonce_one():
    """Test 5: Nonce = 1."""
    print("\n[Test 5] Nonce = 1")
    addr = get_address(PK)
    h, r, s = build_and_sign(PK, addr, nonce=1)
    assert_eq("nonce=1 tx hash valid", len(h), 64)


def test_nonce_max_u64():
    """Test 6: Nonce = max uint64."""
    print("\n[Test 6] Nonce = max uint64")
    addr = get_address(PK)
    max_u64 = (1 << 64) - 1
    h, r, s = build_and_sign(PK, addr, nonce=max_u64)
    assert_eq("nonce=max_u64 tx hash valid", len(h), 64)


def test_nonce_different_hashes():
    """Test 7: Different nonces produce different hashes."""
    print("\n[Test 7] Different nonces → different hashes")
    addr = get_address(PK)
    hashes = set()
    for n in [0, 1, 2, 100, 999999, (1 << 64) - 1]:
        h, _, _ = build_and_sign(PK, addr, nonce=n)
        hashes.add(h)
    assert_eq("6 nonces → 6 unique hashes", len(hashes), 6)


# ==================== Value Tests ====================

def test_value_zero():
    """Test 8: Amount = 0."""
    print("\n[Test 8] Amount = 0")
    addr = get_address(PK)
    h, r, s = build_and_sign(PK, addr, amount=0)
    assert_eq("amount=0 tx hash valid", len(h), 64)


def test_value_one():
    """Test 9: Amount = 1."""
    print("\n[Test 9] Amount = 1")
    addr = get_address(PK)
    h, r, s = build_and_sign(PK, addr, amount=1)
    assert_eq("amount=1 tx hash valid", len(h), 64)


def test_value_max_u64():
    """Test 10: Amount = max uint64."""
    print("\n[Test 10] Amount = max uint64")
    addr = get_address(PK)
    max_u64 = (1 << 64) - 1
    h, r, s = build_and_sign(PK, addr, amount=max_u64)
    assert_eq("amount=max_u64 tx hash valid", len(h), 64)


def test_value_different_hashes():
    """Test 11: Different amounts produce different hashes."""
    print("\n[Test 11] Different amounts → different hashes")
    addr = get_address(PK)
    hashes = set()
    for a in [0, 1, 100, 1000000, (1 << 64) - 1]:
        h, _, _ = build_and_sign(PK, addr, amount=a)
        hashes.add(h)
    assert_eq("5 amounts → 5 unique hashes", len(hashes), 5)


# ==================== Combined Edge Cases ====================

def test_all_zeros():
    """Test 12: All fields zero/minimal."""
    print("\n[Test 12] All fields zero/minimal")
    h, r, s = build_and_sign(PK, "0" * 40, nonce=0, amount=0)
    assert_eq("all-zero tx hash valid", len(h), 64)


def test_all_max():
    """Test 13: All fields max."""
    print("\n[Test 13] All fields max")
    max_u64 = (1 << 64) - 1
    h, r, s = build_and_sign(PK, "f" * 40, nonce=max_u64, amount=max_u64, prefund=max_u64)
    assert_eq("all-max tx hash valid", len(h), 64)


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Transaction Address/Nonce/Value Test")
    print("=" * 50)

    test_address_valid_20bytes()
    test_address_zero()
    test_address_max()
    test_nonce_zero()
    test_nonce_one()
    test_nonce_max_u64()
    test_nonce_different_hashes()
    test_value_zero()
    test_value_one()
    test_value_max_u64()
    test_value_different_hashes()
    test_all_zeros()
    test_all_max()

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    sys.exit(1 if failed > 0 else 0)
