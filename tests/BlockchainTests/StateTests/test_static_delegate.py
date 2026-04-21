"""
Seth chain STATICCALL / DELEGATECALL test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stStaticCall/ + stDelegatecallTestHomestead/

Tests:
  1. STATICCALL: pure add(3,4) = 7
  2. STATICCALL: view getVal after setVal
  3. STATICCALL: state-changing call fails (ok=false)
  4. STATICCALL: revert propagation (ok=false)
  5. DELEGATECALL: setVal changes caller storage
  6. DELEGATECALL: getVal reads caller storage
  7. DELEGATECALL: pure add works
  8. DELEGATECALL: revert propagation (ok=false)
  9. Direct readVal after delegateSetVal

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


def decode_tuple_bool_uint(raw):
    """Decode (bool, uint256) return."""
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) < 128: return False, 0
    ok = int(txt[:64], 16) != 0
    val = int(txt[64:128], 16)
    return ok, val


def decode_bool(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) < 64: return False
    return int(txt[-64:], 16) != 0


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
    with open(os.path.join(SCRIPT_DIR, "StaticDelegateTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    helper_bin = next(v for k, v in comp.items() if k.endswith(":Helper"))["bin"].replace("0x", "").strip()
    main_bin = next(v for k, v in comp.items() if k.endswith(":StaticDelegateTest"))["bin"].replace("0x", "").strip()

    # Deploy Helper
    helper_addr, ok1 = deploy(cli, pk, sender, helper_bin, "Helper")
    assert_true("Helper deploy", ok1)

    if not ok1:
        print("\n  Helper deploy failed, aborting")
        print(f"\nResults: {passed} passed, {failed} failed")
        return failed

    # Deploy main with constructor arg (helper address)
    ctor_arg = eth_abi.encode(["address"], [to_checksum_address("0x" + helper_addr)]).hex()
    full_main_bin = main_bin + ctor_arg
    main_addr, ok2 = deploy(cli, pk, sender, full_main_bin, "StaticDelegateTest")
    assert_true("StaticDelegateTest deploy", ok2)

    if not ok2:
        print("\n  Main deploy failed, aborting")
        print(f"\nResults: {passed} passed, {failed} failed")
        return failed

    # Set helper val to 100 first
    print("\n[Setup] Set helper val=100")
    inp = sel("setVal(uint256)") + eth_abi.encode(["uint256"], [100]).hex()
    tx = cli.send_transaction_auto(pk, helper_addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    cli.wait_for_receipt(tx)
    time.sleep(5)

    # Test 1: STATICCALL add(3,4) = 7
    print("\n[Test 1] STATICCALL: add(3,4)")
    raw = safe_query(cli, sender, main_addr,
        sel("staticAdd(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [3, 4]).hex(),
        "staticAdd")
    if raw:
        ok, result = decode_tuple_bool_uint(raw)
        assert_true("staticAdd ok=true", ok)
        assert_eq("staticAdd result=7", result, 7)
    else:
        assert_true("staticAdd query", False)

    time.sleep(1)

    # Test 2: STATICCALL getVal (should read helper's val=100)
    print("\n[Test 2] STATICCALL: getVal")
    raw = safe_query(cli, sender, main_addr, sel("staticGetVal()"), "staticGetVal")
    if raw:
        ok, result = decode_tuple_bool_uint(raw)
        assert_true("staticGetVal ok=true", ok)
        assert_eq("staticGetVal result=100", result, 100)
    else:
        assert_true("staticGetVal query", False)

    time.sleep(1)

    # Test 3: STATICCALL setVal should fail (state change in static context)
    print("\n[Test 3] STATICCALL: setVal (should fail)")
    raw = safe_query(cli, sender, main_addr,
        sel("staticSetVal(uint256)") + eth_abi.encode(["uint256"], [999]).hex(),
        "staticSetVal")
    if raw:
        ok = decode_bool(raw)
        assert_eq("staticSetVal ok=false", ok, False)
    else:
        assert_true("staticSetVal query", False)

    time.sleep(1)

    # Test 4: STATICCALL revert propagation
    print("\n[Test 4] STATICCALL: revert")
    raw = safe_query(cli, sender, main_addr, sel("staticRevert()"), "staticRevert")
    if raw:
        ok = decode_bool(raw)
        assert_eq("staticRevert ok=false", ok, False)
    else:
        assert_true("staticRevert query", False)

    time.sleep(1)

    # Test 5: DELEGATECALL setVal(777) — changes main's storage
    print("\n[Test 5] DELEGATECALL: setVal(777)")
    inp = sel("delegateSetVal(uint256)") + eth_abi.encode(["uint256"], [777]).hex()
    tx = cli.send_transaction_auto(pk, main_addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("delegateSetVal tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    # Test 6: readVal should be 777 (main's storage changed by delegatecall)
    print("\n[Test 6] readVal after delegateSetVal")
    raw = safe_query(cli, sender, main_addr, sel("readVal()"), "readVal")
    if raw:
        assert_eq("readVal=777", decode_uint256(raw), 777)
    else:
        assert_true("readVal query", False)

    time.sleep(1)

    # Test 7: DELEGATECALL add(10,20) = 30
    print("\n[Test 7] DELEGATECALL: add(10,20)")
    raw = safe_query(cli, sender, main_addr,
        sel("delegateAdd(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [10, 20]).hex(),
        "delegateAdd")
    if raw:
        ok, result = decode_tuple_bool_uint(raw)
        assert_true("delegateAdd ok=true", ok)
        assert_eq("delegateAdd result=30", result, 30)
    else:
        assert_true("delegateAdd query", False)

    time.sleep(1)

    # Test 8: DELEGATECALL revert
    print("\n[Test 8] DELEGATECALL: revert")
    raw = safe_query(cli, sender, main_addr, sel("delegateRevert()"), "delegateRevert")
    if raw:
        ok = decode_bool(raw)
        assert_eq("delegateRevert ok=false", ok, False)
    else:
        assert_true("delegateRevert query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth STATICCALL / DELEGATECALL Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
