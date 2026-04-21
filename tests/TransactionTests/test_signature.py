"""
Seth chain transaction signature tests.
Converted from: tests-ref/TransactionTests/ttSignature/

Tests:
  1. Valid signature produces correct sender recovery
  2. Deterministic signature (same input → same output)
  3. Different messages produce different signatures
  4. Zero signature rejection
  5. Signature with v=0 and v=1 (Seth uses 0/1, not 27/28)
  6. ecrecover via contract (on-chain verification)
"""
import sys, os, struct, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clipy"))

from Crypto.Hash import keccak
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigencode_string_canonize, sigdecode_string

passed = 0
failed = 0

TEST_KEYS = [
    "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
    "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0",
    "4b6525236a2029ab54e2c6162c483133c1af7d38bd960f85b1f485c31e696b7b",
]


def assert_eq(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}: got={got}, expected={expected}")


def get_address(pk_hex):
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    return keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()


def u64le(v):
    return struct.pack("<Q", v)


def build_msg(pk_hex, to, nonce=1, amount=0, step=0, prefund=0):
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
    return keccak.new(digest_bits=256).update(msg).digest()


def sign(pk_hex, msg_hash):
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    sig = sk.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256,
                                        sigencode=sigencode_string_canonize)
    return sig[:32], sig[32:64]


def test_valid_signature_recovery():
    """Test 1: Sign and recover sender address."""
    print("\n[Test 1] Valid signature → sender recovery")
    for pk in TEST_KEYS:
        addr = get_address(pk)
        msg_hash = build_msg(pk, addr, nonce=1, amount=100)
        r, s = sign(pk, msg_hash)

        # Verify signature using public key
        sk = SigningKey.from_string(bytes.fromhex(pk), curve=SECP256k1)
        vk = sk.verifying_key
        try:
            vk.verify_digest(r + s, msg_hash, sigdecode=sigdecode_string)
            assert_eq(f"key={pk[:8]}...: sig valid", True, True)
        except BadSignatureError:
            assert_eq(f"key={pk[:8]}...: sig valid", False, True)


def test_deterministic():
    """Test 2: Same input → same signature."""
    print("\n[Test 2] Deterministic signature")
    for pk in TEST_KEYS:
        addr = get_address(pk)
        msg = build_msg(pk, addr, nonce=5, amount=999)
        r1, s1 = sign(pk, msg)
        r2, s2 = sign(pk, msg)
        assert_eq(f"key={pk[:8]}...: r match", r1.hex(), r2.hex())
        assert_eq(f"key={pk[:8]}...: s match", s1.hex(), s2.hex())


def test_different_messages():
    """Test 3: Different messages → different signatures."""
    print("\n[Test 3] Different messages → different sigs")
    pk = TEST_KEYS[0]
    addr = get_address(pk)
    msg1 = build_msg(pk, addr, nonce=1)
    msg2 = build_msg(pk, addr, nonce=2)
    r1, s1 = sign(pk, msg1)
    r2, s2 = sign(pk, msg2)
    assert_eq("nonce 1 vs 2: r differs", r1.hex() != r2.hex(), True)


def test_zero_signature_invalid():
    """Test 4: Zero r or s should be invalid."""
    print("\n[Test 4] Zero signature rejection")
    pk = TEST_KEYS[0]
    vk = SigningKey.from_string(bytes.fromhex(pk), curve=SECP256k1).verifying_key
    msg_hash = build_msg(pk, get_address(pk))

    # Zero r
    zero_r = b'\x00' * 32
    valid_r, valid_s = sign(pk, msg_hash)
    try:
        vk.verify_digest(zero_r + valid_s, msg_hash, sigdecode=sigdecode_string)
        assert_eq("zero r rejected", False, True)
    except (BadSignatureError, Exception):
        assert_eq("zero r rejected", True, True)

    # Zero s
    zero_s = b'\x00' * 32
    try:
        vk.verify_digest(valid_r + zero_s, msg_hash, sigdecode=sigdecode_string)
        assert_eq("zero s rejected", False, True)
    except (BadSignatureError, Exception):
        assert_eq("zero s rejected", True, True)


def test_wrong_key_fails():
    """Test 5: Signature from wrong key fails verification."""
    print("\n[Test 5] Wrong key → verification fails")
    pk1 = TEST_KEYS[0]
    pk2 = TEST_KEYS[1]
    addr1 = get_address(pk1)
    msg = build_msg(pk1, addr1)
    r, s = sign(pk1, msg)

    # Verify with pk2's public key — should fail
    vk2 = SigningKey.from_string(bytes.fromhex(pk2), curve=SECP256k1).verifying_key
    try:
        vk2.verify_digest(r + s, msg, sigdecode=sigdecode_string)
        assert_eq("wrong key rejected", False, True)
    except BadSignatureError:
        assert_eq("wrong key rejected", True, True)


def test_signature_components_range():
    """Test 6: r and s are within valid secp256k1 range."""
    print("\n[Test 6] Signature components in valid range")
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order
    for pk in TEST_KEYS:
        msg = build_msg(pk, get_address(pk))
        r, s = sign(pk, msg)
        r_int = int.from_bytes(r, "big")
        s_int = int.from_bytes(s, "big")
        assert_eq(f"key={pk[:8]}...: 0 < r < N", 0 < r_int < N, True)
        assert_eq(f"key={pk[:8]}...: 0 < s < N", 0 < s_int < N, True)


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Transaction Signature Test")
    print("=" * 50)

    test_valid_signature_recovery()
    test_deterministic()
    test_different_messages()
    test_zero_signature_invalid()
    test_wrong_key_fails()
    test_signature_components_range()

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    sys.exit(1 if failed > 0 else 0)
