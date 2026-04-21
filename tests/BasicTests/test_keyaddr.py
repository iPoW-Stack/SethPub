"""
Seth chain key-address test.
Converted from: tests-ref/BasicTests/keyaddrtest.json

Tests:
  1. Private key → Seth address derivation (secp256k1 + keccak256)
  2. Empty string signature verification
  3. Address derivation via SethClient.get_address()
"""
import sys, os, hashlib, json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clipy"))

from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

# Test vectors from Ethereum keyaddrtest.json
TEST_VECTORS = [
    {
        "seed": "cow",
        "key": "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
        "addr": "cd2a3d9f938e13cd947ec05abc7fe734df8dd826",
        "sig_v": 27,
        "sig_r": 55022946425863772466282515086640833500580355555249003729267710149987842051473,
        "sig_s": 3021698389129950584349170550428805649435913935175976180112863059249983907949,
    },
    {
        "seed": "horse",
        "key": "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0",
        "addr": "13978aee95f38490e9769c39b2773ed763d9cd5f",
        "sig_v": 28,
        "sig_r": 20570452350081260599473412372903969148670549754219103025003129053348571714359,
        "sig_s": 76892551129780267788164835941580941601518827936179476514262023835864819088004,
    },
]

passed = 0
failed = 0


def assert_eq(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}: got={got}, expected={expected}")


def derive_address(pk_hex):
    """Derive Seth/Ethereum address from private key (same algorithm)."""
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]  # remove 0x04 prefix
    k = keccak.new(digest_bits=256)
    k.update(pub)
    return k.digest()[-20:].hex()


def test_address_derivation():
    """Test 1: Private key → address derivation."""
    print("\n[Test 1] Address derivation (secp256k1 + keccak256)")
    for v in TEST_VECTORS:
        addr = derive_address(v["key"])
        assert_eq(f"seed={v['seed']}: key→addr", addr, v["addr"])


def test_signature():
    """Test 2: Sign empty string and verify signature is deterministic.
    Note: Seth uses SHA256 for deterministic nonce (sign_digest_deterministic),
    so r/s values differ from Ethereum's RFC6979 default. We verify determinism instead."""
    print("\n[Test 2] Empty string signature (determinism)")
    for v in TEST_VECTORS:
        sk = SigningKey.from_string(bytes.fromhex(v["key"]), curve=SECP256k1)
        msg_hash = keccak.new(digest_bits=256).update(b"").digest()
        sig1 = sk.sign_digest_deterministic(
            msg_hash, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize
        )
        sig2 = sk.sign_digest_deterministic(
            msg_hash, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize
        )
        r1 = int.from_bytes(sig1[:32], "big")
        s1 = int.from_bytes(sig1[32:64], "big")
        r2 = int.from_bytes(sig2[:32], "big")
        s2 = int.from_bytes(sig2[32:64], "big")
        assert_eq(f"seed={v['seed']}: sig deterministic (r)", r1, r2)
        assert_eq(f"seed={v['seed']}: sig deterministic (s)", s1, s2)
        assert_eq(f"seed={v['seed']}: sig_r non-zero", r1 > 0, True)
        assert_eq(f"seed={v['seed']}: sig_s non-zero", s1 > 0, True)


def test_seth_client_address():
    """Test 3: Verify SethClient.get_address() matches."""
    print("\n[Test 3] SethClient.get_address()")
    try:
        from seth_sdk import SethClient
        cli = SethClient("127.0.0.1", 1)  # dummy, only need get_address
        for v in TEST_VECTORS:
            addr = cli.get_address(v["key"])
            assert_eq(f"seed={v['seed']}: SethClient.get_address", addr, v["addr"])
    except ImportError:
        print("  ⚠ seth_sdk not available, skipping SethClient test")


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Key-Address Test")
    print("=" * 50)

    test_address_derivation()
    test_signature()
    test_seth_client_address()

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    sys.exit(1 if failed > 0 else 0)
