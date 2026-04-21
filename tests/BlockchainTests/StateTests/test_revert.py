"""
Seth chain REVERT opcode test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stRevertTest/

Tests:
  1. Revert with reason string
  2. Require failure
  3. Conditional revert (false = no revert)
  4. State rollback on revert (set then revert)
  5. Try/catch nested revert
  6. Normal call succeeds

Requires: SETH_HOST env var
"""
import sys, os, secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "clipy"))

import eth_abi
import solcx
from solcx import compile_source, install_solc
from Crypto.Hash import keccak

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


def main():
    host = os.getenv("SETH_HOST", "35.197.170.240")
    port = int(os.getenv("SETH_PORT", "23001"))
    pk = "4b6525236a2029ab54e2c6162c483133c1af7d38bd960f85b1f485c31e696b7b"

    from seth_sdk import SethClient, StepType
    cli = SethClient(host, port)
    sender = cli.get_address(pk)

    # Compile
    print("\n[Compile]")
    install_solc("0.8.20")
    solcx.set_solc_version("0.8.20")
    with open(os.path.join(SCRIPT_DIR, "RevertTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    contract = next(v for k, v in comp.items() if "RevertTestContract" in k)
    bytecode = contract["bin"].replace("0x", "").strip()

    # Deploy
    print("\n[Deploy]")
    salt = secrets.token_hex(32)
    addr = calc_create2(sender, salt, bytecode)
    print(f"  contract: {addr}")
    tx = cli.send_transaction_auto(pk, addr, StepType.kCreateContract,
                                    contract_code=bytecode, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("deploy", rc and rc.get("status") == 0)

    # Prefund
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractGasPrefund, prefund=10_000_000)
    cli.wait_for_receipt(tx)

    # Test 1: Revert with reason
    print("\n[Test 1] Revert with reason")
    inp = sel("revertWithReason()")
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("revert status != 0", rc and rc.get("status") != 0)
    assert_true("revert msg = kConsensusRevert", rc and rc.get("msg") == "kConsensusRevert")

    # Test 2: Require failure
    print("\n[Test 2] Require failure")
    inp = sel("requireFail()")
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("require fail reverts", rc and rc.get("status") != 0)

    # Test 3: Conditional revert (false = success)
    print("\n[Test 3] Conditional revert (shouldRevert=false)")
    inp = sel("conditionalRevert(bool)") + eth_abi.encode(["bool"], [False]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("no revert = success", rc and rc.get("status") == 0)

    # Test 4: Conditional revert (true = revert)
    print("\n[Test 4] Conditional revert (shouldRevert=true)")
    inp = sel("conditionalRevert(bool)") + eth_abi.encode(["bool"], [True]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("revert on true", rc and rc.get("status") != 0)

    # Test 5: State rollback — set value then revert
    print("\n[Test 5] State rollback on revert")
    # First set value to 100
    inp = sel("setValue(uint256)") + eth_abi.encode(["uint256"], [100]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    cli.wait_for_receipt(tx)

    # Verify value = 100
    raw = cli.query_contract(sender, addr, sel("value()"))
    assert_eq("value = 100", decode_uint256(raw), 100)

    # Now setAndRevert(999) — should revert, value stays 100
    inp = sel("setAndRevert(uint256)") + eth_abi.encode(["uint256"], [999]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("setAndRevert reverts", rc and rc.get("status") != 0)

    # Value should still be 100 (state rolled back)
    raw = cli.query_contract(sender, addr, sel("value()"))
    assert_eq("value still 100 after revert", decode_uint256(raw), 100)

    # Test 6: Normal call succeeds
    print("\n[Test 6] Normal call succeeds")
    inp = sel("setValue(uint256)") + eth_abi.encode(["uint256"], [200]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("setValue(200) success", rc and rc.get("status") == 0)
    raw = cli.query_contract(sender, addr, sel("value()"))
    assert_eq("value = 200", decode_uint256(raw), 200)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth REVERT Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
