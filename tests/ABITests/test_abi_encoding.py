"""
Seth chain ABI encoding test.
Converted from: tests-ref/ABITests/basic_abi_tests.json

Tests:
  1. SingleInteger — uint256 encoding
  2. IntegerAndAddress — uint256 + address encoding
  3. GithubWikiTest — mixed types: uint256 + uint32[] + bytes10 + bytes
  4. ABI decode round-trip verification
"""
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clipy"))

import eth_abi
from eth_utils import to_checksum_address

passed = 0
failed = 0


def assert_eq(name, got, expected):
    global passed, failed
    got_clean = got.lower().replace("0x", "")
    exp_clean = expected.lower().replace("0x", "")
    if got_clean == exp_clean:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}")
        print(f"    got:      {got_clean[:80]}...")
        print(f"    expected: {exp_clean[:80]}...")


def test_single_integer():
    """Test 1: Encode single uint256."""
    print("\n[Test 1] SingleInteger: uint256")
    result = eth_abi.encode(["uint256"], [98127491]).hex()
    expected = "0000000000000000000000000000000000000000000000000000000005d94e83"
    assert_eq("uint256(98127491)", result, expected)


def test_integer_and_address():
    """Test 2: Encode uint256 + address."""
    print("\n[Test 2] IntegerAndAddress: uint256 + address")
    result = eth_abi.encode(
        ["uint256", "address"],
        [324124, to_checksum_address("0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826")]
    ).hex()
    expected = (
        "000000000000000000000000000000000000000000000000000000000004f21c"
        "000000000000000000000000cd2a3d9f938e13cd947ec05abc7fe734df8dd826"
    )
    assert_eq("uint256 + address", result, expected)


def test_github_wiki():
    """Test 3: Mixed types — uint256 + uint32[] + bytes10 + bytes."""
    print("\n[Test 3] GithubWikiTest: uint256 + uint32[] + bytes10 + bytes")
    result = eth_abi.encode(
        ["uint256", "uint32[]", "bytes10", "bytes"],
        [
            291,
            [1110, 1929],
            b"1234567890",
            b"Hello, world!",
        ]
    ).hex()
    expected = (
        "0000000000000000000000000000000000000000000000000000000000000123"
        "0000000000000000000000000000000000000000000000000000000000000080"
        "3132333435363738393000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000e0"
        "0000000000000000000000000000000000000000000000000000000000000002"
        "0000000000000000000000000000000000000000000000000000000000000456"
        "0000000000000000000000000000000000000000000000000000000000000789"
        "000000000000000000000000000000000000000000000000000000000000000d"
        "48656c6c6f2c20776f726c642100000000000000000000000000000000000000"
    )
    assert_eq("mixed types", result, expected)


def test_decode_roundtrip():
    """Test 4: Encode then decode, verify values match."""
    print("\n[Test 4] Encode/Decode round-trip")

    # uint256
    encoded = eth_abi.encode(["uint256"], [12345])
    decoded = eth_abi.decode(["uint256"], encoded)
    assert_eq("uint256 round-trip", str(decoded[0]), "12345")

    # address
    addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"
    encoded = eth_abi.encode(["address"], [to_checksum_address(addr)])
    decoded = eth_abi.decode(["address"], encoded)
    assert_eq("address round-trip", decoded[0].lower(), addr.lower())

    # uint32[]
    encoded = eth_abi.encode(["uint32[]"], [[100, 200, 300]])
    decoded = eth_abi.decode(["uint32[]"], encoded)
    assert_eq("uint32[] round-trip", str(list(decoded[0])), "[100, 200, 300]")

    # bytes
    encoded = eth_abi.encode(["bytes"], [b"hello seth"])
    decoded = eth_abi.decode(["bytes"], encoded)
    assert_eq("bytes round-trip", decoded[0].decode(), "hello seth")

    # bool
    encoded = eth_abi.encode(["bool"], [True])
    decoded = eth_abi.decode(["bool"], encoded)
    assert_eq("bool round-trip", str(decoded[0]), "True")

    # int256 negative
    encoded = eth_abi.encode(["int256"], [-42])
    decoded = eth_abi.decode(["int256"], encoded)
    assert_eq("int256 negative round-trip", str(decoded[0]), "-42")

    # tuple
    encoded = eth_abi.encode(["(uint256,address)"], [(999, to_checksum_address(addr))])
    decoded = eth_abi.decode(["(uint256,address)"], encoded)
    assert_eq("tuple round-trip uint", str(decoded[0][0]), "999")
    assert_eq("tuple round-trip addr", decoded[0][1].lower(), addr.lower())


def test_function_selector():
    """Test 5: Function selector (first 4 bytes of keccak256)."""
    print("\n[Test 5] Function selector")
    from Crypto.Hash import keccak

    cases = [
        ("transfer(address,uint256)", "a9059cbb"),
        ("balanceOf(address)", "70a08231"),
        ("approve(address,uint256)", "095ea7b3"),
        ("mint(address,uint256)", "40c10f19"),
    ]
    for sig, expected in cases:
        k = keccak.new(digest_bits=256)
        k.update(sig.encode())
        got = k.digest()[:4].hex()
        assert_eq(f"selector({sig})", got, expected)


if __name__ == "__main__":
    print("=" * 50)
    print("Seth ABI Encoding Test")
    print("=" * 50)

    test_single_integer()
    test_integer_and_address()
    test_github_wiki()
    test_decode_roundtrip()
    test_function_selector()

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    sys.exit(1 if failed > 0 else 0)
