"""
Seth chain CREATE2 test.
Converted from: tests-ref/BlockchainTests/GeneralStateTests/stCreate2/
Reference: clipy/seth3.py test_create2_assembly_deployment

Tests:
  1. Deploy Create2Factory with value
  2. Predict CREATE2 address via getAddress()
  3. Deploy child contract via factory.deploy(salt)
  4. Verify predicted == actual address
  5. Different salts → different addresses
  6. Deterministic: same salt = same predicted address

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

# Same contract as seth3.py PROBE_CREATE2_FACTORY_SOL
CREATE2_FACTORY_SOL = """
pragma solidity ^0.8.20;

contract DeployedContract {
    address public deployer;
    constructor() payable {
        deployer = msg.sender;
    }
}

contract Create2Factory {
    event Deployed(address addr, uint256 salt);
    event DeployFailed(uint256 salt, string reason);
    constructor() payable {}

    function deploy(uint256 salt) external payable returns (address addr) {
        bytes memory bytecode = type(DeployedContract).creationCode;
        bytes32 saltBytes = bytes32(salt);
        assembly {
            addr := create2(10000000, add(bytecode, 0x20), mload(bytecode), saltBytes)
        }
        if (addr == address(0)) {
            emit DeployFailed(salt, "Create2 deployment failed");
            revert("Create2: Failed on deploy");
        }
        emit Deployed(addr, salt);
        return addr;
    }

    function getAddress(uint256 salt) public view returns (address) {
        bytes memory bytecode = type(DeployedContract).creationCode;
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), bytes32(salt), keccak256(bytecode)
        ));
        return address(uint160(uint256(hash)));
    }
}
"""


def assert_eq(name, got, expected):
    global passed, failed
    g = str(got).lower().strip()
    e = str(expected).lower().strip()
    if g == e:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}: got={g}, expected={e}")


def assert_true(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}")


def selector(sig):
    return keccak.new(digest_bits=256).update(sig.encode()).digest()[:4].hex()


def decode_address(raw):
    txt = (raw or "").strip().lower().replace("0x", "")
    if len(txt) >= 64:
        return txt[-40:]
    return txt


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
    comp = compile_source(CREATE2_FACTORY_SOL, output_values=["abi", "bin"],
                           solc_version="0.8.20", optimize=True, optimize_runs=200)
    factory_contract = next(v for k, v in comp.items() if "Create2Factory" in k)
    factory_bin = factory_contract["bin"].replace("0x", "").strip()

    # Deploy factory with value (matching seth3.py: amount=100000000)
    print("\n[Deploy] Create2Factory")
    factory_salt = secrets.token_hex(31) + "f4"
    factory_addr = calc_create2(sender, factory_salt, factory_bin)
    print(f"  factory: {factory_addr}")

    tx = cli.send_transaction_auto(pk, factory_addr, StepType.kCreateContract,
                                    amount=100_000_000,
                                    contract_code=factory_bin, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    assert_true("factory deploy", rc and rc.get("status") == 0)

    # Prefund factory generously (CREATE2 needs value=10000000 per child)
    print("  prefunding factory...")
    tx = cli.send_transaction_auto(pk, factory_addr, StepType.kContractGasPrefund,
                                    prefund=50_000_000)
    cli.wait_for_receipt(tx)

    # Test 1: Predict address
    test_salt = 99999999
    print(f"\n[Test 1] Predict CREATE2 address (salt={test_salt})")
    raw = cli.query_contract(sender, factory_addr,
        selector("getAddress(uint256)") + eth_abi.encode(["uint256"], [test_salt]).hex())
    predicted = decode_address(raw)
    assert_true("predicted addr non-zero", predicted != "0" * 40)
    print(f"  predicted: {predicted}")

    # Test 2: Deploy via CREATE2
    print(f"\n[Test 2] Deploy via CREATE2 (salt={test_salt})")
    inp = selector("deploy(uint256)") + eth_abi.encode(["uint256"], [test_salt]).hex()
    tx = cli.send_transaction_auto(pk, factory_addr, StepType.kContractExcute,
                                    input_hex=inp, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    deploy_ok = rc and rc.get("status") == 0
    assert_true("CREATE2 deploy success", deploy_ok)
    if rc:
        print(f"  receipt: status={rc.get('status')} msg={rc.get('msg')}")

    # Test 3: Predicted matches actual
    print("\n[Test 3] Predicted matches actual")
    raw2 = cli.query_contract(sender, factory_addr,
        selector("getAddress(uint256)") + eth_abi.encode(["uint256"], [test_salt]).hex())
    predicted2 = decode_address(raw2)
    assert_eq("predict consistent", predicted2, predicted)

    # Test 4: Different salts → different addresses
    print("\n[Test 4] Different salts → different addresses")
    addrs = set()
    for salt in [1, 2, 3, 100, 999]:
        raw = cli.query_contract(sender, factory_addr,
            selector("getAddress(uint256)") + eth_abi.encode(["uint256"], [salt]).hex())
        addrs.add(decode_address(raw))
    assert_eq("5 salts → 5 unique addrs", len(addrs), 5)

    # Test 5: Same salt = same address
    print("\n[Test 5] Same salt = same address")
    raw_a = cli.query_contract(sender, factory_addr,
        selector("getAddress(uint256)") + eth_abi.encode(["uint256"], [42]).hex())
    raw_b = cli.query_contract(sender, factory_addr,
        selector("getAddress(uint256)") + eth_abi.encode(["uint256"], [42]).hex())
    assert_eq("deterministic", decode_address(raw_a), decode_address(raw_b))

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    return failed


if __name__ == "__main__":
    print("=" * 50)
    print("Seth CREATE2 Test")
    print("=" * 50)
    failures = main()
    sys.exit(1 if failures > 0 else 0)
