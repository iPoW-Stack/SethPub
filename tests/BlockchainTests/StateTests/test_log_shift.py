"""
Seth chain LOG + SHIFT opcode tests.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stLogTests/ + stShift/

Tests:
  LOG: LOG0-LOG3, Transfer event, multiple events in one tx
  SHIFT: SHL, SHR, SAR, edge cases (max, zero, overflow)

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
    with open(os.path.join(SCRIPT_DIR, "LogShiftTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    contract = next(v for k, v in comp.items() if "LogShiftTestContract" in k)
    bytecode = contract["bin"].replace("0x", "").strip()

    salt = secrets.token_hex(32)
    addr = calc_create2(sender, salt, bytecode)
    tx = cli.send_transaction_auto(pk, addr, StepType.kCreateContract,
                                    contract_code=bytecode, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("deploy", rc and rc.get("status") == 0)
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractGasPrefund, prefund=10_000_000)
    cli.wait_for_receipt(tx)

    # ==================== LOG Tests ====================
    print("\n[LOG Tests]")

    # LOG0
    inp = sel("emitLog0(uint256)") + eth_abi.encode(["uint256"], [42]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute, input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("LOG0 success", rc and rc.get("status") == 0)
    assert_true("LOG0 has events", rc and len(rc.get("events", [])) > 0)

    # LOG1
    inp = sel("emitLog1(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [1, 100]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute, input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("LOG1 success", rc and rc.get("status") == 0)
    assert_true("LOG1 has events", rc and len(rc.get("events", [])) > 0)

    # LOG2
    inp = sel("emitLog2(uint256,uint256,uint256)") + eth_abi.encode(["uint256", "uint256", "uint256"], [1, 2, 200]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute, input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("LOG2 success", rc and rc.get("status") == 0)

    # LOG3
    inp = sel("emitLog3(uint256,uint256,uint256,uint256)") + eth_abi.encode(["uint256"]*4, [1, 2, 3, 300]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute, input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("LOG3 success", rc and rc.get("status") == 0)

    # Transfer event (indexed address)
    inp = sel("emitTransfer(address,uint256)") + eth_abi.encode(
        ["address", "uint256"], [to_checksum_address("0x" + sender), 1000]).hex()
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute, input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("Transfer event success", rc and rc.get("status") == 0)

    # Multiple events
    inp = sel("emitMultiple()")
    tx = cli.send_transaction_auto(pk, addr, StepType.kContractExcute, input_hex=inp, prefund=5_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("multiple events success", rc and rc.get("status") == 0)
    event_count = len(rc.get("events", [])) if rc else 0
    assert_eq("3 events emitted", event_count, 3)

    # ==================== SHIFT Tests ====================
    print("\n[SHIFT Tests]")

    # SHL
    raw = cli.query_contract(sender, addr, sel("shl(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [4, 1]).hex())
    assert_eq("SHL 1<<4 = 16", decode_uint256(raw), 16)

    # SHR
    raw = cli.query_contract(sender, addr, sel("shr(uint256,uint256)") + eth_abi.encode(["uint256", "uint256"], [4, 256]).hex())
    assert_eq("SHR 256>>4 = 16", decode_uint256(raw), 16)

    # SAR (arithmetic right shift on negative)
    raw = cli.query_contract(sender, addr, sel("sar(uint256,int256)") + eth_abi.encode(["uint256", "int256"], [1, -4]).hex())
    # -4 >> 1 = -2 (arithmetic shift preserves sign)
    result = decode_uint256(raw)
    # -2 in uint256 = 2^256 - 2
    expected = (1 << 256) - 2
    assert_eq("SAR -4>>1 = -2", result, expected)

    # Edge: shift 0
    raw = cli.query_contract(sender, addr, sel("shlZero()"))
    assert_eq("SHL 42<<0 = 42", decode_uint256(raw), 42)

    raw = cli.query_contract(sender, addr, sel("shrZero()"))
    assert_eq("SHR 42>>0 = 42", decode_uint256(raw), 42)

    # Edge: shift max
    raw = cli.query_contract(sender, addr, sel("shlMax()"))
    assert_eq("SHL 1<<255", decode_uint256(raw), 1 << 255)

    raw = cli.query_contract(sender, addr, sel("shrMax()"))
    assert_eq("SHR max>>1", decode_uint256(raw), ((1 << 256) - 1) >> 1)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth LOG + SHIFT Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
