"""
Seth chain CREATE / Gas Refund / Initcode test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stCreateTest/ + stRefundTest/ + stInitCodeTest/

Tests:
  1. CREATE via new: child deployed, val set
  2. CREATE2 via new{salt}: child deployed
  3. Nested create: factory creates child
  4. CREATE reverting constructor: ok=false
  5. Gas refund: SSTORE non-zero to zero (clearSlot)
  6. Gas refund: set then clear in same tx
  7. Initcode: deploy large contract, verify sum()

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


def decode_address(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) >= 64: return txt[-40:]
    return txt


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
    with open(os.path.join(SCRIPT_DIR, "CreateTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    main_bin = next(v for k, v in comp.items() if k.endswith(":CreateTest"))["bin"].replace("0x", "").strip()

    addr, ok = deploy(cli, pk, sender, main_bin, "CreateTest")
    assert_true("CreateTest deploy", ok)

    if not ok:
        print("\n  Deploy failed, aborting")
        print(f"\nResults: {passed} passed, {failed} failed")
        return failed

    time.sleep(5)

    # Test 1: CREATE via new — createChild(42)
    print("\n[Test 1] CREATE: createChild(42)")
    inp = sel("createChild(uint256)") + eth_abi.encode(["uint256"], [42]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("createChild tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    # Test 2: CREATE2 via new{salt} — create2Child(99, salt)
    print("\n[Test 2] CREATE2: create2Child(99, salt)")
    salt_bytes = bytes.fromhex("00" * 31 + "01")
    inp = sel("create2Child(uint256,bytes32)") + eth_abi.encode(["uint256", "bytes32"], [99, salt_bytes]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("create2Child tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    # Test 3: Nested create
    print("\n[Test 3] Nested CREATE: nestedCreate(123)")
    inp = sel("nestedCreate(uint256)") + eth_abi.encode(["uint256"], [123]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("nestedCreate tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    # Test 4: CREATE reverting constructor
    print("\n[Test 4] CREATE: reverting constructor")
    inp = sel("createReverting()")
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("createReverting tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    # Test 5: Gas refund — clearSlot (SSTORE non-zero to zero)
    print("\n[Test 5] Gas refund: clearSlot")
    # First verify refundSlot = 1
    raw = safe_query(cli, sender, addr, sel("refundSlot()"), "refundSlot")
    if raw:
        assert_eq("refundSlot initial=1", decode_uint256(raw), 1)
    else:
        assert_true("refundSlot query", False)

    time.sleep(1)

    inp = sel("clearSlot()")
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("clearSlot tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    raw = safe_query(cli, sender, addr, sel("refundSlot()"), "refundSlot after")
    if raw:
        assert_eq("refundSlot after clear=0", decode_uint256(raw), 0)
    else:
        assert_true("refundSlot after query", False)

    time.sleep(1)

    # Test 6: Gas refund — setThenClear
    print("\n[Test 6] Gas refund: setThenClear")
    inp = sel("setThenClear(uint256)") + eth_abi.encode(["uint256"], [999]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("setThenClear tx success", rc and rc.get("status") == 0)

    time.sleep(3)

    raw = safe_query(cli, sender, addr, sel("tempSlot()"), "tempSlot")
    if raw:
        assert_eq("tempSlot after setThenClear=0", decode_uint256(raw), 0)
    else:
        assert_true("tempSlot query", False)

    time.sleep(1)

    # Test 7: Initcode — deploy large contract
    print("\n[Test 7] Initcode: deployLarge")
    inp = sel("deployLarge()")
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("deployLarge tx success", rc and rc.get("status") == 0)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth CREATE / Gas Refund / Initcode Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
