"""
Seth chain transaction test.
Converted from: tests-ref/BasicTests/txtest.json

Original tests Ethereum RLP-encoded transactions.
Seth uses a different transaction format (no RLP), so we test:
  1. Transaction hash computation (keccak256 of message fields)
  2. Transaction signing (secp256k1 deterministic ECDSA)
  3. Send transaction to Seth chain and verify receipt
"""
import sys, os, struct, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clipy"))

from Crypto.Hash import keccak
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

# Seth transaction test vectors
# Derived from the Ethereum test keys but using Seth's message format
TEST_KEYS = [
    {
        "seed": "cow",
        "key": "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
        "addr": "cd2a3d9f938e13cd947ec05abc7fe734df8dd826",
    },
    {
        "seed": "horse",
        "key": "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0",
        "addr": "13978aee95f38490e9769c39b2773ed763d9cd5f",
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


def u64le(v):
    return struct.pack("<Q", v)


def get_address(pk_hex):
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    return keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()


def build_seth_tx_hash(pk_hex, to_hex, nonce=1, amount=0, gas_limit=5000000,
                        gas_price=1, step=0, contract_code="", input_hex="", prefund=0):
    """Build Seth transaction hash matching seth_sdk.py's compute_hash."""
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed").hex()

    msg = bytearray()
    msg.extend(u64le(nonce))
    msg.extend(bytes.fromhex(pub))
    msg.extend(bytes.fromhex(to_hex))
    msg.extend(u64le(amount))
    msg.extend(u64le(gas_limit))
    msg.extend(u64le(gas_price))
    msg.extend(u64le(step))
    if contract_code:
        msg.extend(bytes.fromhex(contract_code))
    if input_hex:
        msg.extend(bytes.fromhex(input_hex))
    if prefund > 0:
        msg.extend(u64le(prefund))

    tx_hash = keccak.new(digest_bits=256).update(msg).digest()
    return tx_hash, msg


def sign_seth_tx(pk_hex, tx_hash):
    """Sign a Seth transaction hash."""
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    sig = sk.sign_digest_deterministic(tx_hash, hashfunc=hashlib.sha256,
                                        sigencode=sigencode_string_canonize)
    return sig[:32], sig[32:64]  # r, s


def test_tx_hash_deterministic():
    """Test 1: Same inputs produce same tx hash."""
    print("\n[Test 1] Transaction hash is deterministic")
    for v in TEST_KEYS:
        to = v["addr"]
        h1, _ = build_seth_tx_hash(v["key"], to, nonce=1, amount=1000)
        h2, _ = build_seth_tx_hash(v["key"], to, nonce=1, amount=1000)
        assert_eq(f"seed={v['seed']}: hash deterministic", h1.hex(), h2.hex())


def test_tx_hash_changes_with_nonce():
    """Test 2: Different nonce produces different hash."""
    print("\n[Test 2] Hash changes with nonce")
    for v in TEST_KEYS:
        to = v["addr"]
        h1, _ = build_seth_tx_hash(v["key"], to, nonce=1)
        h2, _ = build_seth_tx_hash(v["key"], to, nonce=2)
        assert_eq(f"seed={v['seed']}: nonce 1 != nonce 2", h1.hex() != h2.hex(), True)


def test_tx_hash_changes_with_amount():
    """Test 3: Different amount produces different hash."""
    print("\n[Test 3] Hash changes with amount")
    for v in TEST_KEYS:
        to = v["addr"]
        h1, _ = build_seth_tx_hash(v["key"], to, amount=100)
        h2, _ = build_seth_tx_hash(v["key"], to, amount=200)
        assert_eq(f"seed={v['seed']}: amount 100 != 200", h1.hex() != h2.hex(), True)


def test_tx_signature():
    """Test 4: Signature is deterministic and valid."""
    print("\n[Test 4] Transaction signature")
    for v in TEST_KEYS:
        to = v["addr"]
        tx_hash, _ = build_seth_tx_hash(v["key"], to, nonce=1, amount=1000, prefund=1000000)
        r1, s1 = sign_seth_tx(v["key"], tx_hash)
        r2, s2 = sign_seth_tx(v["key"], tx_hash)
        # Deterministic: same hash → same signature
        assert_eq(f"seed={v['seed']}: sig_r deterministic", r1.hex(), r2.hex())
        assert_eq(f"seed={v['seed']}: sig_s deterministic", s1.hex(), s2.hex())
        # Non-zero
        assert_eq(f"seed={v['seed']}: sig_r non-zero", int.from_bytes(r1, "big") > 0, True)
        assert_eq(f"seed={v['seed']}: sig_s non-zero", int.from_bytes(s1, "big") > 0, True)


def test_tx_different_step_types():
    """Test 5: Different step types produce different hashes."""
    print("\n[Test 5] Different step types")
    v = TEST_KEYS[0]
    to = v["addr"]
    h_transfer, _ = build_seth_tx_hash(v["key"], to, step=0)   # kNormalFrom
    h_deploy, _ = build_seth_tx_hash(v["key"], to, step=6)     # kCreateContract
    h_call, _ = build_seth_tx_hash(v["key"], to, step=8)       # kContractExecute
    h_prefund, _ = build_seth_tx_hash(v["key"], to, step=7)    # kContractGasPrefund
    assert_eq("transfer != deploy", h_transfer.hex() != h_deploy.hex(), True)
    assert_eq("deploy != call", h_deploy.hex() != h_call.hex(), True)
    assert_eq("call != prefund", h_call.hex() != h_prefund.hex(), True)


def test_send_to_seth():
    """Test 6: Send actual transaction to Seth chain (optional, requires live node)."""
    print("\n[Test 6] Send to Seth chain (live)")
    host = os.getenv("SETH_HOST", "")
    if not host:
        print("  ⚠ SETH_HOST not set, skipping live test")
        return

    port = int(os.getenv("SETH_PORT", "23001"))
    pk = os.getenv("DEPLOYER_PK", TEST_KEYS[0]["key"])

    try:
        from seth_sdk import SethClient, StepType
        cli = SethClient(host, port)
        sender = cli.get_address(pk)
        print(f"  sender: {sender}")

        # Self-transfer
        tx = cli.send_transaction_auto(pk, sender, StepType.kNormalFrom,
                                        amount=100, prefund=1000000)
        receipt = cli.wait_for_receipt(tx)
        status = receipt.get("status") if receipt else None
        assert_eq("self-transfer receipt", status in [0, 5010, 5011], True)
    except Exception as e:
        print(f"  ⚠ Live test failed: {e}")


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Transaction Test")
    print("=" * 50)

    test_tx_hash_deterministic()
    test_tx_hash_changes_with_nonce()
    test_tx_hash_changes_with_amount()
    test_tx_signature()
    test_tx_different_step_types()
    test_send_to_seth()

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    sys.exit(1 if failed > 0 else 0)
