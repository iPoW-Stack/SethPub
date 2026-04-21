"""
Seth chain MEMORY / STACK / RETURNDATA test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stMemoryTest/ + stStackTests/ + stReturnDataTest/

Tests:
  1. MSTORE/MLOAD round-trip
  2. MSTORE8 single byte
  3. MSIZE grows with access
  4. CALLDATACOPY
  5. Large memory allocation
  6. KECCAK256 of memory
  7. Stack DUP/SWAP via computation
  8. Stack deep computation
  9. Stack multiple returns
  10. Return dynamic bytes
  11. Return empty bytes
  12. RETURNDATASIZE

Requires: SETH_HOST env var
"""
import sys, os, secrets, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "clipy"))

import eth_abi
import solcx
from solcx import compile_source, install_solc
from Crypto.Hash import keccak
from eth_utils import to_checksum_address

passed = 0
failed = 0
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def assert_eq(name, got, expected):
    global passed, failed
    if str(got).lower().strip() == str(expected).lower().strip():
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}: got={got}, expected={expected}")


def assert_true(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}")


def sel(sig):
    return keccak.new(digest_bits=256).update(sig.encode()).digest()[:4].hex()


def decode_uint256(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) < 64: return 0
    return int(txt[-64:], 16)


def decode_two_uint256(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) < 128: return 0, 0
    return int(txt[:64], 16), int(txt[64:128], 16)


def decode_three_uint256(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) < 192: return 0, 0, 0
    return int(txt[:64], 16), int(txt[64:128], 16), int(txt[128:192], 16)


def decode_bytes32(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) >= 64: return txt[:64]
    return txt


def calc_create2(deployer, salt_hex, bytecode_hex):
    d = bytes.fromhex(deployer)
    s = bytes.fromhex(salt_hex.zfill(64))
    c = bytes.fromhex(bytecode_hex)
    kc = keccak.new(digest_bits=256); kc.update(c)
    kf = keccak.new(digest_bits=256)
    kf.update(b"\xff" + d + s + kc.digest())
    return kf.digest()[-20:].hex()


def safe_query(cli, sender, addr, calldata, label):
    try:
        return cli.query_contract(sender, addr, calldata)
    except Exception as e:
        print(f"  ✗ {label}: query failed - {e}")
        return None


def deploy(cli, pk, sender, bytecode, label):
    from seth_sdk import StepType
    salt = secrets.token_hex(32)
    addr = calc_create2(sender, salt, bytecode)
    print(f"  {label}: {addr}")
    tx = cli.send_transaction_auto(pk, addr, StepType.kCreateContract,
                                    contract_code=bytecode, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    time.sleep(2)
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractGasPrefund, prefund=10_000_000)
    cli.wait_for_receipt(tx)
    time.sleep(2)
    return addr, rc and rc.get("status") == 0


def main():
    host = os.getenv("SETH_HOST", "35.197.170.240")
    port = int(os.getenv("SETH_PORT", "23001"))
    pk = "4b6525236a2029ab54e2c6162c483133c1af7d38bd960f85b1f485c31e696b7b"

    from seth_sdk import SethClient, StepType
    cli = SethClient(host, port)
    sender = cli.get_address(pk)

    print("\n[Compile & Deploy]")
    install_solc("0.8.20")
    solcx.set_solc_version("0.8.20")
    with open(os.path.join(SCRIPT_DIR, "MemoryStackTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    bytecode = next(v for k, v in comp.items() if k.endswith(":MemoryStackTest"))["bin"].replace("0x", "").strip()

    addr, ok = deploy(cli, pk, sender, bytecode, "MemoryStackTest")
    assert_true("deploy", ok)

    if not ok:
        print("\n  Deploy failed, aborting")
        print(f"\nResults: {passed} passed, {failed} failed")
        return failed

    time.sleep(5)

    # Test 1: MSTORE/MLOAD
    print("\n[Test 1] MSTORE/MLOAD round-trip")
    raw = safe_query(cli, sender, addr,
        sel("memStoreLoad(uint256)") + eth_abi.encode(["uint256"], [12345]).hex(), "memStoreLoad")
    if raw:
        assert_eq("memStoreLoad(12345)=12345", decode_uint256(raw), 12345)
    else:
        assert_true("memStoreLoad query", False)

    time.sleep(1)

    # Test 2: MSTORE8
    print("\n[Test 2] MSTORE8")
    raw = safe_query(cli, sender, addr,
        sel("memStore8(uint8)") + eth_abi.encode(["uint8"], [0xAB]).hex(), "memStore8")
    if raw:
        assert_eq("memStore8(0xAB)=0xAB", decode_uint256(raw), 0xAB)
    else:
        assert_true("memStore8 query", False)

    time.sleep(1)

    # Test 3: MSTORE at 0x100 and read back
    print("\n[Test 3] MSTORE at offset 0x100")
    raw = safe_query(cli, sender, addr, sel("memSize()"), "memSize")
    if raw:
        val = decode_uint256(raw)
        assert_eq("mstore(0x100,1) read back=1", val, 1)
    else:
        assert_true("memSize query", False)

    time.sleep(1)

    # Test 4: CALLDATACOPY
    print("\n[Test 4] CALLDATACOPY")
    raw = safe_query(cli, sender, addr,
        sel("calldataCopyTest(uint256)") + eth_abi.encode(["uint256"], [9999]).hex(), "calldataCopy")
    if raw:
        assert_eq("calldataCopy(9999)=9999", decode_uint256(raw), 9999)
    else:
        assert_true("calldataCopy query", False)

    time.sleep(1)

    # Test 5: Large memory
    print("\n[Test 5] Large memory allocation")
    raw = safe_query(cli, sender, addr, sel("memLargeAlloc()"), "memLargeAlloc")
    if raw:
        val = decode_uint256(raw)
        assert_eq("mstore(0x1000,42) read back=42", val, 42)
    else:
        assert_true("memLargeAlloc query", False)

    time.sleep(1)

    # Test 6: KECCAK256
    print("\n[Test 6] KECCAK256 of memory")
    raw = safe_query(cli, sender, addr,
        sel("memKeccak(uint256)") + eth_abi.encode(["uint256"], [42]).hex(), "memKeccak")
    if raw:
        h = decode_bytes32(raw)
        # Compute expected: keccak256(abi.encode(42))
        expected = keccak.new(digest_bits=256).update(eth_abi.encode(["uint256"], [42])).hexdigest()
        assert_eq("keccak256(42) matches", h, expected)
    else:
        assert_true("memKeccak query", False)

    time.sleep(1)

    # Test 7: Stack DUP/SWAP
    print("\n[Test 7] Stack DUP/SWAP")
    raw = safe_query(cli, sender, addr,
        sel("stackDupSwap(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [10, 3]).hex(),
        "stackDupSwap")
    if raw:
        s, d = decode_two_uint256(raw)
        assert_eq("sum=13", s, 13)
        assert_eq("diff=7", d, 7)
    else:
        assert_true("stackDupSwap query", False)

    time.sleep(1)

    # Test 8: Stack deep
    print("\n[Test 8] Stack deep computation")
    raw = safe_query(cli, sender, addr,
        sel("stackDeep(uint256)") + eth_abi.encode(["uint256"], [100]).hex(), "stackDeep")
    if raw:
        # 100+1+2+3+4+5+6+7+8 = 136
        assert_eq("stackDeep(100)=136", decode_uint256(raw), 136)
    else:
        assert_true("stackDeep query", False)

    time.sleep(1)

    # Test 9: Stack multiple returns
    print("\n[Test 9] Stack multiple returns")
    raw = safe_query(cli, sender, addr,
        sel("stackMultiReturn(uint256)") + eth_abi.encode(["uint256"], [5]).hex(), "stackMultiReturn")
    if raw:
        a, b, c = decode_three_uint256(raw)
        assert_eq("ret[0]=5", a, 5)
        assert_eq("ret[1]=10", b, 10)
        assert_eq("ret[2]=15", c, 15)
    else:
        assert_true("stackMultiReturn query", False)

    time.sleep(1)

    # Test 10: Return dynamic bytes
    print("\n[Test 10] Return dynamic bytes")
    raw = safe_query(cli, sender, addr,
        sel("returnDynamic(uint256)") + eth_abi.encode(["uint256"], [4]).hex(), "returnDynamic")
    if raw:
        txt = (raw or "").strip().lower().replace("0x", "")
        # Dynamic bytes: offset(32) + length(32) + data
        if len(txt) >= 192:
            length = int(txt[64:128], 16)
            assert_eq("dynamic bytes length=4", length, 4)
        else:
            assert_true("returnDynamic parse", False)
    else:
        assert_true("returnDynamic query", False)

    time.sleep(1)

    # Test 11: Return empty
    print("\n[Test 11] Return empty bytes")
    raw = safe_query(cli, sender, addr, sel("returnEmpty()"), "returnEmpty")
    if raw:
        txt = (raw or "").strip().lower().replace("0x", "")
        if len(txt) >= 128:
            length = int(txt[64:128], 16)
            assert_eq("empty bytes length=0", length, 0)
        else:
            assert_true("returnEmpty parse", False)
    else:
        assert_true("returnEmpty query", False)

    time.sleep(1)

    # Test 12: RETURNDATASIZE
    print("\n[Test 12] RETURNDATASIZE")
    raw = safe_query(cli, sender, addr,
        sel("getReturnDataSize(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + addr)]).hex(),
        "getReturnDataSize")
    if raw:
        rdsize = decode_uint256(raw)
        assert_true(f"returndatasize > 0 (got {rdsize})", rdsize > 0)
    else:
        assert_true("getReturnDataSize query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Memory / Stack / ReturnData Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
