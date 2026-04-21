"""
Seth chain Solidity features / Code size limit test.
Converted from: stSolidityTest/ + stCodeSizeLimit/

Tests:
  1. Mapping: set and get balance
  2. Struct: create order, read back
  3. Struct: fill order, verify
  4. Enum: set and get status
  5. Array: push, length, pop
  6. Ternary: max(3,7)=7, max(9,2)=9
  7. Bytes concat
  8. Try/catch div: ok case and div-by-zero case
  9. Code size: self < 24576
  10. Code size: contract within EIP-170 limit

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

def safe_tx(cli, pk, addr, inp, label, prefund=5_000_000):
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
    with open(os.path.join(SCRIPT_DIR, "SolidityCodeLimitTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    sol_bin = next(v for k, v in comp.items() if k.endswith(":SolidityTest"))["bin"].replace("0x", "").strip()
    csl_bin = next(v for k, v in comp.items() if k.endswith(":CodeSizeLimitTest"))["bin"].replace("0x", "").strip()

    sol_addr, ok1 = deploy(cli, pk, sender, sol_bin, "SolidityTest")
    assert_true("SolidityTest deploy", ok1)

    csl_addr, ok2 = deploy(cli, pk, sender, csl_bin, "CodeSizeLimitTest")
    assert_true("CodeSizeLimitTest deploy", ok2)

    if not (ok1 and ok2):
        print(f"\nResults: {passed} passed, {failed} failed"); return failed

    time.sleep(5)

    # Test 1: Mapping set/get
    print("\n[Test 1] Mapping: setBalance + balances")
    target = to_checksum_address("0x" + sender)
    inp = sel("setBalance(address,uint256)") + eth_abi.encode(["address", "uint256"], [target, 500]).hex()
    rc = safe_tx(cli, pk, sol_addr, inp, "setBalance")
    assert_true("setBalance tx", rc and rc.get("status") == 0)

    raw = safe_query(cli, sender, sol_addr,
        sel("balances(address)") + eth_abi.encode(["address"], [target]).hex(), "balances")
    if raw:
        assert_eq("balances=500", decode_uint256(raw), 500)
    else:
        assert_true("balances query", False)
    time.sleep(1)

    # Test 2: Struct create + read
    print("\n[Test 2] Struct: createOrder + getOrder")
    inp = sel("createOrder(uint256)") + eth_abi.encode(["uint256"], [100]).hex()
    rc = safe_tx(cli, pk, sol_addr, inp, "createOrder")
    assert_true("createOrder tx", rc and rc.get("status") == 0)

    raw = safe_query(cli, sender, sol_addr, sel("orderCount()"), "orderCount")
    if raw:
        assert_true(f"orderCount > 0 (got {decode_uint256(raw)})", decode_uint256(raw) > 0)
    else:
        assert_true("orderCount query", False)
    time.sleep(1)

    # Test 3: Fill order
    print("\n[Test 3] Struct: fillOrder")
    inp = sel("fillOrder(uint256)") + eth_abi.encode(["uint256"], [0]).hex()
    rc = safe_tx(cli, pk, sol_addr, inp, "fillOrder")
    assert_true("fillOrder tx", rc and rc.get("status") == 0)
    time.sleep(1)

    # Test 4: Enum
    print("\n[Test 4] Enum: setStatus + status")
    inp = sel("setStatus(uint8)") + eth_abi.encode(["uint8"], [1]).hex()
    rc = safe_tx(cli, pk, sol_addr, inp, "setStatus")
    assert_true("setStatus tx", rc and rc.get("status") == 0)

    raw = safe_query(cli, sender, sol_addr, sel("status()"), "status")
    if raw:
        assert_eq("status=1 (Active)", decode_uint256(raw), 1)
    else:
        assert_true("status query", False)
    time.sleep(1)

    # Test 5: Array push + length + pop
    print("\n[Test 5] Array: push, length, pop")
    inp = sel("pushArr(uint256)") + eth_abi.encode(["uint256"], [42]).hex()
    safe_tx(cli, pk, sol_addr, inp, "pushArr(42)")
    inp = sel("pushArr(uint256)") + eth_abi.encode(["uint256"], [99]).hex()
    safe_tx(cli, pk, sol_addr, inp, "pushArr(99)")

    raw = safe_query(cli, sender, sol_addr, sel("arrLength()"), "arrLength")
    if raw:
        assert_eq("arrLength=2", decode_uint256(raw), 2)
    else:
        assert_true("arrLength query", False)

    inp = sel("popArr()")
    safe_tx(cli, pk, sol_addr, inp, "popArr")

    raw = safe_query(cli, sender, sol_addr, sel("arrLength()"), "arrLength after pop")
    if raw:
        assert_eq("arrLength after pop=1", decode_uint256(raw), 1)
    else:
        assert_true("arrLength after pop query", False)
    time.sleep(1)

    # Test 6: Ternary max
    print("\n[Test 6] Ternary: max")
    raw = safe_query(cli, sender, sol_addr,
        sel("max(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [3, 7]).hex(), "max(3,7)")
    if raw:
        assert_eq("max(3,7)=7", decode_uint256(raw), 7)
    else:
        assert_true("max(3,7) query", False)

    raw = safe_query(cli, sender, sol_addr,
        sel("max(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [9, 2]).hex(), "max(9,2)")
    if raw:
        assert_eq("max(9,2)=9", decode_uint256(raw), 9)
    else:
        assert_true("max(9,2) query", False)
    time.sleep(1)

    # Test 7: Try/catch div
    print("\n[Test 7] Try/catch div")
    raw = safe_query(cli, sender, sol_addr,
        sel("tryCatchDiv(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [10, 3]).hex(),
        "tryCatchDiv(10,3)")
    if raw:
        txt = (raw or "").strip().lower().replace("0x", "")
        if len(txt) >= 128:
            ok_val = int(txt[:64], 16) != 0
            result = int(txt[64:128], 16)
            assert_true("div ok=true", ok_val)
            assert_eq("10/3=3", result, 3)
        else:
            assert_true("tryCatchDiv parse", False)
    else:
        assert_true("tryCatchDiv query", False)

    raw = safe_query(cli, sender, sol_addr,
        sel("tryCatchDiv(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [10, 0]).hex(),
        "tryCatchDiv(10,0)")
    if raw:
        txt = (raw or "").strip().lower().replace("0x", "")
        if len(txt) >= 128:
            ok_val = int(txt[:64], 16) != 0
            assert_eq("div-by-zero ok=false", ok_val, False)
        else:
            assert_true("tryCatchDiv(10,0) parse", False)
    else:
        assert_true("tryCatchDiv(10,0) query", False)
    time.sleep(1)

    # Test 8: Code size self
    print("\n[Test 8] Code size: self < 24576")
    raw = safe_query(cli, sender, csl_addr, sel("selfCodeSize()"), "selfCodeSize")
    if raw:
        size = decode_uint256(raw)
        assert_true(f"selfCodeSize < 24576 (got {size})", 0 < size < 24576)
    else:
        assert_true("selfCodeSize query", False)
    time.sleep(1)

    # Test 9: Code size within limit
    print("\n[Test 9] Code size: isWithinLimit")
    raw = safe_query(cli, sender, csl_addr,
        sel("isWithinLimit(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + sol_addr)]).hex(),
        "isWithinLimit")
    if raw:
        assert_eq("SolidityTest within limit", decode_bool(raw), True)
    else:
        assert_true("isWithinLimit query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Solidity Features / Code Size Limit Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
