"""
Seth chain EXTCODESIZE/EXTCODEHASH/EXTCODECOPY/CHAINID/SELFBALANCE test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stExtCodeHash/ + stCodeCopyTest/ + stChainId/ + stSelfBalance/

Tests:
  1. EXTCODESIZE: contract has code > 0
  2. EXTCODESIZE: EOA has code = 0
  3. EXTCODEHASH: contract has non-zero hash
  4. EXTCODEHASH: two calls return same hash
  5. CODESIZE: own code size > 0
  6. EXTCODECOPY: copied code length matches EXTCODESIZE
  7. isContract: true for contract, false for EOA
  8. ADDRESS: returns own address
  9. CHAINID: returns non-zero

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


def decode_bytes32(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) >= 64: return txt[:64]
    return txt


def decode_address(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) >= 64: return txt[-40:]
    return txt


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
    """Query contract with error handling — returns None on failure."""
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

    # Compile
    print("\n[Compile & Deploy]")
    install_solc("0.8.20")
    solcx.set_solc_version("0.8.20")
    with open(os.path.join(SCRIPT_DIR, "CodeTestContract.sol"), "r", encoding="utf-8") as f:
        src = f.read()
    comp = compile_source(src, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    code_bin = next(v for k, v in comp.items() if k.endswith(":CodeTestContract"))["bin"].replace("0x", "").strip()
    target_bin = next(v for k, v in comp.items() if k.endswith(":SimpleTarget"))["bin"].replace("0x", "").strip()

    code_addr, ok1 = deploy(cli, pk, sender, code_bin, "CodeTestContract")
    assert_true("CodeTestContract deploy", ok1)

    target_addr, ok2 = deploy(cli, pk, sender, target_bin, "SimpleTarget")
    assert_true("SimpleTarget deploy", ok2)

    if not (ok1 and ok2):
        print("\n  Deploy failed, skipping query tests")
        print(f"\n{'=' * 50}")
        print(f"Results: {passed} passed, {failed} failed")
        print("=" * 50)
        return failed

    # Wait longer for node HTTPS connection pool to recover after deploy phase
    print("\n  Waiting 15s for node connection pool to recover...")
    time.sleep(15)

    # Test 1: EXTCODESIZE of contract > 0
    print("\n[Test 1] EXTCODESIZE: contract")
    raw = safe_query(cli, sender, code_addr,
        sel("getCodeSize(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + target_addr)]).hex(),
        "EXTCODESIZE contract")
    if raw is not None:
        size = decode_uint256(raw)
        assert_true(f"target code size > 0 (got {size})", size > 0)
    else:
        size = 0
        assert_true("EXTCODESIZE contract query", False)

    time.sleep(1)

    # Test 2: EXTCODESIZE of EOA = 0
    print("\n[Test 2] EXTCODESIZE: EOA")
    raw = safe_query(cli, sender, code_addr,
        sel("getCodeSize(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + sender)]).hex(),
        "EXTCODESIZE EOA")
    if raw is not None:
        assert_eq("EOA code size = 0", decode_uint256(raw), 0)
    else:
        assert_true("EXTCODESIZE EOA query", False)

    time.sleep(1)

    # Test 3: EXTCODEHASH of contract != 0
    print("\n[Test 3] EXTCODEHASH: contract")
    raw = safe_query(cli, sender, code_addr,
        sel("getCodeHash(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + target_addr)]).hex(),
        "EXTCODEHASH contract")
    if raw is not None:
        hash1 = decode_bytes32(raw)
        assert_true(f"target code hash != 0", hash1 != "0" * 64)
    else:
        hash1 = None
        assert_true("EXTCODEHASH contract query", False)

    time.sleep(1)

    # Test 4: EXTCODEHASH deterministic
    print("\n[Test 4] EXTCODEHASH: deterministic")
    raw2 = safe_query(cli, sender, code_addr,
        sel("getCodeHash(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + target_addr)]).hex(),
        "EXTCODEHASH deterministic")
    if raw2 is not None and hash1 is not None:
        hash2 = decode_bytes32(raw2)
        assert_eq("hash consistent", hash1, hash2)
    else:
        assert_true("EXTCODEHASH deterministic query", False)

    time.sleep(1)

    # Test 5: CODESIZE own
    print("\n[Test 5] CODESIZE: own")
    raw = safe_query(cli, sender, code_addr, sel("getOwnCodeSize()"), "CODESIZE own")
    if raw is not None:
        own_size = decode_uint256(raw)
        assert_true(f"own code size > 0 (got {own_size})", own_size > 0)
    else:
        assert_true("CODESIZE own query", False)

    time.sleep(1)

    # Test 6: EXTCODECOPY length matches
    print("\n[Test 6] EXTCODECOPY: length matches EXTCODESIZE")
    raw = safe_query(cli, sender, code_addr,
        sel("getCode(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + target_addr)]).hex(),
        "EXTCODECOPY")
    if raw is not None:
        raw_hex = (raw or "").strip().lower().replace("0x", "")
        if len(raw_hex) >= 128:
            copied_len = int(raw_hex[64:128], 16)
            assert_eq("copied code length = extcodesize", copied_len, size)
        else:
            assert_true("EXTCODECOPY parse", False)
    else:
        assert_true("EXTCODECOPY query", False)

    time.sleep(1)

    # Test 7: isContract
    print("\n[Test 7] isContract")
    raw = safe_query(cli, sender, code_addr,
        sel("isContract(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + target_addr)]).hex(),
        "isContract(contract)")
    if raw is not None:
        assert_eq("target isContract = true", decode_bool(raw), True)
    else:
        assert_true("isContract(contract) query", False)

    time.sleep(1)

    raw = safe_query(cli, sender, code_addr,
        sel("isContract(address)") + eth_abi.encode(["address"], [to_checksum_address("0x" + sender)]).hex(),
        "isContract(EOA)")
    if raw is not None:
        assert_eq("EOA isContract = false", decode_bool(raw), False)
    else:
        assert_true("isContract(EOA) query", False)

    time.sleep(1)

    # Test 8: ADDRESS
    print("\n[Test 8] ADDRESS")
    raw = safe_query(cli, sender, code_addr, sel("getAddress()"), "ADDRESS")
    if raw is not None:
        assert_eq("address = self", decode_address(raw), code_addr)
    else:
        assert_true("ADDRESS query", False)

    time.sleep(1)

    # Test 9: CHAINID
    print("\n[Test 9] CHAINID")
    raw = safe_query(cli, sender, code_addr, sel("getChainId()"), "CHAINID")
    if raw is not None:
        chain_id = decode_uint256(raw)
        assert_true(f"chainId > 0 (got {chain_id})", chain_id > 0)
    else:
        assert_true("CHAINID query", False)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth Code/Env Opcode Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
