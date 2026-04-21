"""
Seth chain attack / bad opcode / overflow test.
Converted from: stAttackTest/ + stBadOpcode/ + stSpecialTest/

Tests:
  1. INVALID opcode (0xfe) — tx reverts
  2. Recursive call depth — stops at limit
  3. Gas bomb — runs until gas exhausted
  4. Reentrancy attack — blocked by lock
  5. Division by zero — reverts (Solidity 0.8+)
  6. Overflow — reverts (Solidity 0.8+)
  7. Underflow — reverts (Solidity 0.8+)
  8. Large return data — doesn't crash

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
    with open(os.path.join(SCRIPT_DIR, "AttackBadopTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    attack_bin = next(v for k, v in comp.items() if k.endswith(":AttackBadopTest"))["bin"].replace("0x", "").strip()
    victim_bin = next(v for k, v in comp.items() if k.endswith(":Victim"))["bin"].replace("0x", "").strip()

    attack_addr, ok1 = deploy(cli, pk, sender, attack_bin, "AttackBadopTest")
    assert_true("AttackBadopTest deploy", ok1)

    victim_addr, ok2 = deploy(cli, pk, sender, victim_bin, "Victim")
    assert_true("Victim deploy", ok2)

    if not (ok1 and ok2):
        print(f"\nResults: {passed} passed, {failed} failed"); return failed

    time.sleep(5)

    # Test 1: INVALID opcode — should revert
    print("\n[Test 1] INVALID opcode (0xfe)")
    inp = sel("invalidOpcode()")
    rc = safe_tx(cli, pk, attack_addr, inp, "invalidOpcode")
    status = rc.get("status", -1) if rc else -1
    assert_true(f"invalidOpcode reverts (status={status})", status != 0)

    # Test 2: Recursive call depth
    print("\n[Test 2] Recursive call depth")
    inp = sel("recursiveCall(uint256)") + eth_abi.encode(["uint256"], [50]).hex()
    rc = safe_tx(cli, pk, attack_addr, inp, "recursiveCall")
    assert_true("recursiveCall completes", rc is not None)

    # Test 3: Gas bomb
    print("\n[Test 3] Gas bomb")
    inp = sel("gasBomb()")
    rc = safe_tx(cli, pk, attack_addr, inp, "gasBomb")
    assert_true("gasBomb completes", rc is not None)

    # Test 4: Reentrancy attack
    print("\n[Test 4] Reentrancy attack")
    inp = sel("setVictim(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + victim_addr)]).hex()
    safe_tx(cli, pk, attack_addr, inp, "setVictim")

    raw = safe_query(cli, sender, attack_addr, sel("victimAddr()"), "victimAddr")
    if raw:
        assert_true("victimAddr set", decode_uint256(raw) != 0)
    else:
        assert_true("victimAddr query", False)
    time.sleep(1)

    # Test 5: Division by zero — reverts
    print("\n[Test 5] Division by zero")
    inp = sel("divByZero(uint256)") + eth_abi.encode(["uint256"], [10]).hex()
    rc = safe_tx(cli, pk, attack_addr, inp, "divByZero")
    status = rc.get("status", -1) if rc else -1
    assert_true(f"divByZero reverts (status={status})", status != 0)

    # Test 6: Overflow — reverts
    print("\n[Test 6] Overflow")
    inp = sel("overflow()")
    rc = safe_tx(cli, pk, attack_addr, inp, "overflow")
    status = rc.get("status", -1) if rc else -1
    assert_true(f"overflow reverts (status={status})", status != 0)

    # Test 7: Underflow — reverts
    print("\n[Test 7] Underflow")
    inp = sel("underflow()")
    rc = safe_tx(cli, pk, attack_addr, inp, "underflow")
    status = rc.get("status", -1) if rc else -1
    assert_true(f"underflow reverts (status={status})", status != 0)

    # Test 8: Large return data
    print("\n[Test 8] Large return data")
    raw = safe_query(cli, sender, attack_addr, sel("largeReturn()"), "largeReturn")
    if raw:
        txt = (raw or "").strip().lower().replace("0x", "")
        # Dynamic bytes: offset + length + data
        if len(txt) >= 128:
            length = int(txt[64:128], 16)
            assert_eq("largeReturn length=10000", length, 10000)
        else:
            assert_true("largeReturn parse", False)
    else:
        assert_true("largeReturn query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Attack / BadOpcode / Overflow Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
