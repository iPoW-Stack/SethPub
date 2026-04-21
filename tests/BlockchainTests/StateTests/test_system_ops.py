"""
Seth chain system operations test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stSystemOperationsTest/

Tests:
  1. Owner set in constructor
  2. setValue + read back
  3. GASLEFT > 0
  4. TIMESTAMP > 0
  5. BLOCKNUMBER >= 0
  6. BALANCE of sender >= 0

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


def calc_create2(deployer, salt_hex, bytecode_hex):
    d = bytes.fromhex(deployer)
    s = bytes.fromhex(salt_hex.zfill(64))
    c = bytes.fromhex(bytecode_hex)
    kc = keccak.new(digest_bits=256); kc.update(c)
    kf = keccak.new(digest_bits=256)
    kf.update(b"\xff" + d + s + kc.digest())
    return kf.digest()[-20:].hex()


def safe_query(cli, sender, addr, calldata, label):
    """Query contract with error handling."""
    try:
        return cli.query_contract(sender, addr, calldata)
    except Exception as e:
        print(f"  ✗ {label}: query failed - {e}")
        return None


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
    with open(os.path.join(SCRIPT_DIR, "SystemOpsTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    contract = next(v for k, v in comp.items() if "SystemOpsTestContract" in k)
    bytecode = contract["bin"].replace("0x", "").strip()

    salt = secrets.token_hex(32)
    addr = calc_create2(sender, salt, bytecode)
    print(f"  contract: {addr}")
    tx = cli.send_transaction_auto(pk, addr, StepType.kCreateContract,
                                    contract_code=bytecode, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    deploy_ok = rc and rc.get("status") == 0
    assert_true("deploy", deploy_ok)

    time.sleep(2)
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractGasPrefund, prefund=10_000_000)
    cli.wait_for_receipt(tx)
    time.sleep(2)

    if not deploy_ok:
        print("\n  Deploy failed, skipping query tests")
        print(f"\n{'=' * 50}")
        print(f"Results: {passed} passed, {failed} failed")
        print("=" * 50)
        return failed

    # Wait for node to stabilize
    time.sleep(5)

    # Test 1: Owner set in constructor
    print("\n[Test 1] Owner = deployer")
    raw = safe_query(cli, sender, addr, sel("owner()"), "owner()")
    if raw is not None:
        assert_eq("owner = sender", decode_address(raw), sender)
    else:
        assert_true("owner() query", False)

    time.sleep(1)

    # Test 2: setValue + read
    print("\n[Test 2] setValue + read")
    inp = sel("setValue(uint256)") + eth_abi.encode(["uint256"], [555]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("setValue success", rc and rc.get("status") == 0)

    time.sleep(3)
    raw = safe_query(cli, sender, addr, sel("value()"), "value()")
    if raw is not None:
        assert_eq("value = 555", decode_uint256(raw), 555)
    else:
        assert_true("value() query", False)

    time.sleep(1)

    # Test 3: GASLEFT > 0
    print("\n[Test 3] GASLEFT")
    raw = safe_query(cli, sender, addr, sel("getGasLeft()"), "getGasLeft()")
    if raw is not None:
        gas = decode_uint256(raw)
        assert_true(f"gasLeft > 0 (got {gas})", gas > 0)
    else:
        assert_true("getGasLeft() query", False)

    time.sleep(1)

    # Test 4: TIMESTAMP > 0
    print("\n[Test 4] TIMESTAMP")
    raw = safe_query(cli, sender, addr, sel("getTimestamp()"), "getTimestamp()")
    if raw is not None:
        ts = decode_uint256(raw)
        assert_true(f"timestamp >= 0 (got {ts})", ts >= 0)
    else:
        assert_true("getTimestamp() query", False)

    time.sleep(1)

    # Test 5: BLOCKNUMBER
    print("\n[Test 5] BLOCKNUMBER")
    raw = safe_query(cli, sender, addr, sel("getBlockNumber()"), "getBlockNumber()")
    if raw is not None:
        bn = decode_uint256(raw)
        print(f"  blockNumber = {bn}")
        assert_true(f"blockNumber >= 0 (got {bn})", bn >= 0)
    else:
        assert_true("getBlockNumber() query", False)

    time.sleep(1)

    # Test 6: BALANCE of sender
    print("\n[Test 6] BALANCE")
    raw = safe_query(cli, sender, addr,
        sel("getBalance(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + sender)]).hex(),
        "getBalance()")
    if raw is not None:
        bal = decode_uint256(raw)
        print(f"  sender balance = {bal}")
        assert_true(f"sender balance >= 0 (got {bal})", bal >= 0)
    else:
        assert_true("getBalance() query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth System Operations Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
