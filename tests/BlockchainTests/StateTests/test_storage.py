"""
Seth chain SSTORE/SLOAD storage test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stSStoreTest/ + stSLoadTest/

Tests:
  1. Basic SSTORE + SLOAD
  2. Set and read in same tx
  3. Multiple slot writes
  4. Clear storage (write zero)
  5. Mapping storage
  6. Address mapping
  7. Dynamic array push/read
  8. Overwrite same slot multiple times
  9. Read uninitialized slot = 0

Requires: SETH_HOST env var
"""
import sys, os, secrets

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


def calc_create2(deployer, salt_hex, bytecode_hex):
    d = bytes.fromhex(deployer)
    s = bytes.fromhex(salt_hex.zfill(64))
    c = bytes.fromhex(bytecode_hex)
    kc = keccak.new(digest_bits=256); kc.update(c)
    kf = keccak.new(digest_bits=256)
    kf.update(b"\xff" + d + s + kc.digest())
    return kf.digest()[-20:].hex()


def call_tx(cli, pk, addr, sig, types=None, args=None):
    from seth_sdk import StepType
    inp = sel(sig)
    if types and args:
        inp += eth_abi.encode(types, args).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    return cli.wait_for_receipt(tx)


def query(cli, sender, addr, sig, types=None, args=None):
    inp = sel(sig)
    if types and args:
        inp += eth_abi.encode(types, args).hex()
    return cli.query_contract(sender, addr, inp)


def main():
    host = os.getenv("SETH_HOST", "35.197.170.240")
    port = int(os.getenv("SETH_PORT", "23001"))
    pk = "4b6525236a2029ab54e2c6162c483133c1af7d38bd960f85b1f485c31e696b7b"

    from seth_sdk import SethClient, StepType
    cli = SethClient(host, port)
    sender = cli.get_address(pk)

    # Compile & Deploy
    print("\n[Compile & Deploy]")
    install_solc("0.8.20")
    solcx.set_solc_version("0.8.20")
    with open(os.path.join(SCRIPT_DIR, "StorageTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    contract = next(v for k, v in comp.items() if "StorageTestContract" in k)
    bytecode = contract["bin"].replace("0x", "").strip()

    salt = secrets.token_hex(32)
    addr = calc_create2(sender, salt, bytecode)
    tx = cli.send_transaction_auto(pk, addr, StepType.kCreateContract,
                                    contract_code=bytecode, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("deploy", rc and rc.get("status") == 0)
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractGasPrefund, prefund=10_000_000)
    cli.wait_for_receipt(tx)

    # Test 1: Basic SSTORE + SLOAD
    print("\n[Test 1] Basic SSTORE + SLOAD")
    call_tx(cli, pk, addr, "setSlot0(uint256)", ["uint256"], [42])
    assert_eq("slot0 = 42", decode_uint256(query(cli, sender, addr, "slot0()")), 42)

    # Test 2: Set and read in same tx
    print("\n[Test 2] Set and read in same tx")
    rc = call_tx(cli, pk, addr, "setAndGet(uint256)", ["uint256"], [123])
    assert_true("setAndGet success", rc and rc.get("status") == 0)
    assert_eq("slot0 = 123", decode_uint256(query(cli, sender, addr, "slot0()")), 123)

    # Test 3: Multiple slot writes
    print("\n[Test 3] Multiple slot writes")
    call_tx(cli, pk, addr, "multiWrite(uint256,uint256)", ["uint256", "uint256"], [100, 200])
    assert_eq("slot0 = 100", decode_uint256(query(cli, sender, addr, "slot0()")), 100)
    assert_eq("slot1 = 200", decode_uint256(query(cli, sender, addr, "slot1()")), 200)

    # Test 4: Clear storage
    print("\n[Test 4] Clear storage (write zero)")
    call_tx(cli, pk, addr, "clearSlot0()")
    assert_eq("slot0 = 0", decode_uint256(query(cli, sender, addr, "slot0()")), 0)

    # Test 5: Mapping
    print("\n[Test 5] Mapping storage")
    call_tx(cli, pk, addr, "setMap(uint256,uint256)", ["uint256", "uint256"], [7, 777])
    assert_eq("map[7] = 777", decode_uint256(query(cli, sender, addr, "getMap(uint256)", ["uint256"], [7])), 777)
    assert_eq("map[8] = 0", decode_uint256(query(cli, sender, addr, "getMap(uint256)", ["uint256"], [8])), 0)

    # Test 6: Address mapping
    print("\n[Test 6] Address mapping")
    test_addr = to_checksum_address("0x" + sender)
    call_tx(cli, pk, addr, "setBalance(address,uint256)", ["address", "uint256"], [test_addr, 9999])
    assert_eq("balances[sender] = 9999",
              decode_uint256(query(cli, sender, addr, "getBalance(address)", ["address"], [test_addr])), 9999)

    # Test 7: Dynamic array
    print("\n[Test 7] Dynamic array")
    call_tx(cli, pk, addr, "pushArr(uint256)", ["uint256"], [10])
    call_tx(cli, pk, addr, "pushArr(uint256)", ["uint256"], [20])
    call_tx(cli, pk, addr, "pushArr(uint256)", ["uint256"], [30])
    assert_eq("arr.length = 3", decode_uint256(query(cli, sender, addr, "getArrLen()")), 3)
    assert_eq("arr[0] = 10", decode_uint256(query(cli, sender, addr, "getArr(uint256)", ["uint256"], [0])), 10)
    assert_eq("arr[2] = 30", decode_uint256(query(cli, sender, addr, "getArr(uint256)", ["uint256"], [2])), 30)

    # Test 8: Overwrite same slot
    print("\n[Test 8] Overwrite same slot multiple times")
    call_tx(cli, pk, addr, "overwriteMany(uint256,uint256,uint256)",
            ["uint256", "uint256", "uint256"], [1, 2, 3])
    assert_eq("slot0 = 3 (last write wins)", decode_uint256(query(cli, sender, addr, "slot0()")), 3)

    # Test 9: Read uninitialized
    print("\n[Test 9] Read uninitialized slot")
    assert_eq("uninitialized = 0", decode_uint256(query(cli, sender, addr, "readUninitialized()")), 0)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth SSTORE/SLOAD Storage Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
