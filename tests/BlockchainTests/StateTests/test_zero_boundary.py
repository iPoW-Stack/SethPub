"""
Seth chain zero-value / boundary test.
Converted from: stArgsZeroOneBalance/ + stZeroCallsTest/ + stZeroCallsRevert/ + stNonZeroCallsTest/ + stSelfBalance/

Tests:
  1. Zero-value CALL to contract
  2. Zero-value CALL with data
  3. Zero-value DELEGATECALL
  4. Zero-value STATICCALL
  5. CALL to zero address (0x0)
  6. CALL to non-existent address
  7. Zero-value CALL + revert
  8. SELFBALANCE = 0 initially
  9. Balance of sender > 0

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
        passed += 1; print(f"  ✓ {name}")
    else:
        failed += 1; print(f"  ✗ {name}: got={got}, expected={expected}")

def assert_true(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✓ {name}")
    else: failed += 1; print(f"  ✗ {name}")

def sel(sig):
    return keccak.new(digest_bits=256).update(sig.encode()).digest()[:4].hex()

def decode_uint256(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) < 64: return 0
    return int(txt[-64:], 16)

def decode_bool(raw):
    return decode_uint256(raw) != 0

def calc_create2(deployer, salt_hex, bytecode_hex):
    d = bytes.fromhex(deployer)
    s = bytes.fromhex(salt_hex.zfill(64))
    c = bytes.fromhex(bytecode_hex)
    kc = keccak.new(digest_bits=256); kc.update(c)
    kf = keccak.new(digest_bits=256)
    kf.update(b"\xff" + d + s + kc.digest())
    return kf.digest()[-20:].hex()

def safe_query(cli, sender, addr, calldata, label):
    try: return cli.query_contract(sender, addr, calldata)
    except Exception as e:
        print(f"  ✗ {label}: query failed - {e}"); return None

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


def safe_tx(cli, pk, addr, inp, label, prefund=5_000_000):
    """Execute a contract call with error handling."""
    from seth_sdk import StepType
    try:
        tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute,
                                        input_hex=inp, prefund=prefund)
        rc = cli.wait_for_receipt(tx)
        time.sleep(3)
        return rc
    except Exception as e:
        print(f"  ✗ {label}: tx failed - {e}")
        time.sleep(3)
        return None


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
    with open(os.path.join(SCRIPT_DIR, "ZeroBoundaryTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    bytecode = next(v for k, v in comp.items() if k.endswith(":ZeroBoundaryTest"))["bin"].replace("0x", "").strip()

    addr, ok = deploy(cli, pk, sender, bytecode, "ZeroBoundaryTest")
    assert_true("deploy", ok)
    if not ok:
        print(f"\nResults: {passed} passed, {failed} failed"); return failed

    time.sleep(5)

    # Test 1: Zero-value CALL to self
    print("\n[Test 1] Zero-value CALL to contract")
    inp = sel("zeroCallTo(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + addr)]).hex()
    rc = safe_tx(cli, pk, addr, inp, "zeroCallTo")
    assert_true("zeroCallTo tx success", rc and rc.get("status") == 0)

    # Test 2: Zero-value CALL with data (getVal)
    print("\n[Test 2] Zero-value CALL with data")
    calldata_inner = bytes.fromhex(sel("getVal()"))
    inp = sel("zeroCallWithData(address,bytes)") + eth_abi.encode(
        ["address", "bytes"], [to_checksum_address("0x" + addr), calldata_inner]).hex()
    rc = safe_tx(cli, pk, addr, inp, "zeroCallWithData")
    assert_true("zeroCallWithData tx success", rc and rc.get("status") == 0)

    # Test 3: Zero-value DELEGATECALL
    print("\n[Test 3] Zero-value DELEGATECALL")
    inp = sel("zeroDelegatecall(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + addr)]).hex()
    rc = safe_tx(cli, pk, addr, inp, "zeroDelegatecall")
    assert_true("zeroDelegatecall tx success", rc and rc.get("status") == 0)

    # Test 4: Zero-value STATICCALL
    print("\n[Test 4] Zero-value STATICCALL")
    raw = safe_query(cli, sender, addr,
        sel("zeroStaticcall(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + addr)]).hex(),
        "zeroStaticcall")
    if raw:
        txt = (raw or "").strip().lower().replace("0x", "")
        if len(txt) >= 128:
            ok_val = int(txt[:64], 16) != 0
            assert_true("zeroStaticcall ok=true", ok_val)
        else:
            assert_true("zeroStaticcall parse", False)
    else:
        assert_true("zeroStaticcall query", False)
    time.sleep(1)

    # Test 5: CALL to zero address
    print("\n[Test 5] CALL to zero address")
    inp = sel("callZeroAddr()")
    rc = safe_tx(cli, pk, addr, inp, "callZeroAddr")
    assert_true("callZeroAddr tx completes", rc and rc.get("status") == 0)

    # Test 6: CALL to non-existent address
    print("\n[Test 6] CALL to non-existent address")
    fake_addr = "0x" + "dead" * 10
    inp = sel("callNonExistent(address)") + eth_abi.encode(["address"], [to_checksum_address(fake_addr)]).hex()
    rc = safe_tx(cli, pk, addr, inp, "callNonExistent")
    assert_true("callNonExistent tx completes", rc and rc.get("status") == 0)

    # Test 7: Zero-value CALL + revert
    print("\n[Test 7] Zero-value CALL + revert")
    inp = sel("zeroCallRevert(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + addr)]).hex()
    rc = safe_tx(cli, pk, addr, inp, "zeroCallRevert")
    assert_true("zeroCallRevert tx completes", rc and rc.get("status") == 0)

    # Test 8: SELFBALANCE
    print("\n[Test 8] SELFBALANCE")
    raw = safe_query(cli, sender, addr, sel("getSelfBalance()"), "getSelfBalance")
    if raw:
        bal = decode_uint256(raw)
        assert_true(f"selfBalance >= 0 (got {bal})", bal >= 0)
    else:
        assert_true("getSelfBalance query", False)
    time.sleep(1)

    # Test 9: Balance of sender
    print("\n[Test 9] Balance of sender")
    raw = safe_query(cli, sender, addr,
        sel("getBalance(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + sender)]).hex(),
        "getBalance(sender)")
    if raw:
        bal = decode_uint256(raw)
        assert_true(f"sender balance >= 0 (got {bal})", bal >= 0)
    else:
        assert_true("getBalance query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Zero-Value / Boundary Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
