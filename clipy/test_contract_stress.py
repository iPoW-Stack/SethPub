#!/usr/bin/env python3
"""
AMM Contract Stress Test — Python equivalent of tx_cli.cc Mode 5

Phases:
  1. Compile SimpleToken + AMMPool contracts
  2. Generate user + deployer accounts, fund them
  3. Deploy TokenA, TokenB, AMMPool per deployer
  4. Deployer: prefund + approve + addLiquidity
  5. User: prefund + approve + swap stress test
  6. Report TPS

Usage:
  python3 test_contract_stress.py <ip> <port> <funder_key> [users] [contract_sets] [rounds]

Example:
  python3 test_contract_stress.py 127.0.0.1 23001 7c5b4ec6...66 100 10 20
"""

from __future__ import annotations
import sys, os, time, secrets, struct, hashlib, random, json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from Crypto.Hash import keccak
import eth_abi

from seth_sdk import SethWeb3Mock, StepType, compile_and_link


# ── Constants ────────────────────────────────────────────────────────────────

SIMPLE_TOKEN_SOL = """
pragma solidity ^0.8.0;

contract SimpleToken {
    bytes32 public name;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(bytes32 _name, uint256 _initialSupply) {
        name = _name;
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "not approved");
        require(balanceOf[from] >= amount, "insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
"""

AMM_POOL_SOL = """
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AMMPool {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidity;

    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 lp);
    event Swap(address indexed user, address tokenIn, uint256 amountIn, uint256 amountOut);

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 lp) {
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
        if (totalLiquidity == 0) { lp = amountA; }
        else { lp = (amountA * totalLiquidity) / reserveA; }
        reserveA += amountA;
        reserveB += amountB;
        totalLiquidity += lp;
        liquidity[msg.sender] += lp;
        emit LiquidityAdded(msg.sender, amountA, amountB, lp);
    }

    function swapAForB(uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(amountIn > 0 && reserveA > 0 && reserveB > 0, "invalid");
        amountOut = (amountIn * reserveB) / (reserveA + amountIn);
        require(amountOut >= minOut, "slippage");
        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);
        reserveA += amountIn;
        reserveB -= amountOut;
        emit Swap(msg.sender, address(tokenA), amountIn, amountOut);
    }

    function swapBForA(uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(amountIn > 0 && reserveA > 0 && reserveB > 0, "invalid");
        amountOut = (amountIn * reserveA) / (reserveB + amountIn);
        require(amountOut >= minOut, "slippage");
        tokenB.transferFrom(msg.sender, address(this), amountIn);
        tokenA.transfer(msg.sender, amountOut);
        reserveB += amountIn;
        reserveA -= amountOut;
        emit Swap(msg.sender, address(tokenB), amountIn, amountOut);
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserveA, reserveB);
    }
}
"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256).update(data).digest()


def make_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    pk_hex = sk.to_string().hex()
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    addr = keccak256(pub)[-20:].hex()
    return pk_hex, addr


def get_address(pk_hex: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    return keccak256(pub)[-20:].hex()


def encode_call(selector_hex: str, types: list, values: list) -> str:
    """Encode a contract call: 4-byte selector + ABI-encoded args."""
    return selector_hex + eth_abi.encode(types, values).hex()


def func_selector(sig: str) -> str:
    """Compute 4-byte function selector from signature like 'approve(address,uint256)'."""
    return keccak256(sig.encode())[:4].hex()


# ── Main Test ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    funder_key = sys.argv[3]
    user_count = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    contract_sets = int(sys.argv[5]) if len(sys.argv) > 5 else 10
    stress_rounds = int(sys.argv[6]) if len(sys.argv) > 6 else 20

    w3 = SethWeb3Mock(ip, port)
    funder_addr = w3.client.get_address(funder_key)

    print(f"\n{'='*70}")
    print(f"  AMM Contract Stress Test")
    print(f"  Users: {user_count}, Contract Sets: {contract_sets}")
    print(f"  Stress Rounds: {stress_rounds}")
    print(f"  Node: {ip}:{port}")
    print(f"  Funder: {funder_addr}")
    print(f"{'='*70}")

    # ── Phase 1: Compile contracts ───────────────────────────────────────
    print(f"\n[Phase 1] Compiling contracts...")
    token_bin, token_abi = compile_and_link(SIMPLE_TOKEN_SOL, "SimpleToken")
    pool_bin, pool_abi = compile_and_link(AMM_POOL_SOL, "AMMPool")
    print(f"  SimpleToken bytecode: {len(token_bin)} chars")
    print(f"  AMMPool bytecode: {len(pool_bin)} chars")

    # ── Phase 2: Generate accounts ───────────────────────────────────────
    print(f"\n[Phase 2] Generating {user_count} users + {contract_sets} deployers...")
    users = [make_keypair() for _ in range(user_count)]
    deployers = [make_keypair() for _ in range(contract_sets)]
    print(f"  ✓ Generated {user_count + contract_sets} accounts")

    # ── Phase 3: Fund all accounts ───────────────────────────────────────
    print(f"\n[Phase 3] Funding all accounts...")
    fund_amount = 3_000_000_000
    all_accounts = users + deployers

    for i, (_, addr) in enumerate(all_accounts):
        tx_hash = w3.client.send_transaction_auto(
            funder_key, addr, StepType.kNormalFrom, amount=fund_amount)
        if (i + 1) % 100 == 0:
            print(f"  Funded {i+1}/{len(all_accounts)}")
        time.sleep(0.05)

    print(f"  ✓ Funding sent for {len(all_accounts)} accounts")

    # Wait and verify
    print(f"  Waiting 15s for consensus...")
    time.sleep(15)

    verified = 0
    for _, addr in all_accounts:
        bal = w3.client.get_balance(addr)
        if bal > 0:
            verified += 1
    print(f"  ✓ Verified: {verified}/{len(all_accounts)}")

    if verified < len(all_accounts) * 0.8:
        print("  ✗ Too many accounts unverified. Aborting.")
        sys.exit(1)

    # ── Phase 4: Deploy contracts ────────────────────────────────────────
    print(f"\n[Phase 4] Deploying {contract_sets} AMM contract sets (3 each)...")

    class AMMSet:
        def __init__(self):
            self.token_a_addr = ""
            self.token_b_addr = ""
            self.pool_addr = ""
            self.deployer_key = ""
            self.deployer_addr = ""
            self.ok = False

    amm_sets: List[AMMSet] = []

    for i in range(contract_sets):
        dk, da = deployers[i]
        s = AMMSet()
        s.deployer_key = dk
        s.deployer_addr = da

        try:
            # Deploy TokenA
            name_a = f"TkA_{i}".encode().ljust(32, b'\x00')
            contract_a = w3.seth.contract(abi=token_abi, bytecode=token_bin, sender_address=da)
            contract_a = contract_a.deploy({
                'from': da, 'salt': secrets.token_hex(31) + 'a',
                'args': [name_a, 10_000_000]
            }, dk)
            s.token_a_addr = contract_a.address

            # Deploy TokenB
            name_b = f"TkB_{i}".encode().ljust(32, b'\x00')
            contract_b = w3.seth.contract(abi=token_abi, bytecode=token_bin, sender_address=da)
            contract_b = contract_b.deploy({
                'from': da, 'salt': secrets.token_hex(31) + 'b',
                'args': [name_b, 10_000_000]
            }, dk)
            s.token_b_addr = contract_b.address

            # Deploy AMMPool
            contract_p = w3.seth.contract(abi=pool_abi, bytecode=pool_bin, sender_address=da)
            contract_p = contract_p.deploy({
                'from': da, 'salt': secrets.token_hex(31) + 'c',
                'args': [s.token_a_addr, s.token_b_addr]
            }, dk)
            s.pool_addr = contract_p.address
            s.ok = True

        except Exception as e:
            print(f"  ✗ Set {i} deploy failed: {e}")

        amm_sets.append(s)
        if (i + 1) % 5 == 0:
            ok_count = sum(1 for x in amm_sets if x.ok)
            print(f"  Deployed {i+1}/{contract_sets} (ok={ok_count})")

    ok_sets = [s for s in amm_sets if s.ok]
    print(f"  ✓ Deployed: {len(ok_sets)}/{contract_sets} complete AMM sets")

    if not ok_sets:
        print("  ✗ No contracts deployed. Aborting.")
        sys.exit(1)

    # Wait for contract deployment consensus
    print(f"  Waiting 15s for contract consensus...")
    time.sleep(15)

    # ── Phase 5: Deployer prefund + approve + addLiquidity ───────────────
    print(f"\n[Phase 5] Setting up liquidity...")
    prefund_amount = 800_000_000
    initial_liquidity = 5_000_000

    for i, s in enumerate(ok_sets):
        dk = s.deployer_key
        try:
            # Prefund on all 3 contracts
            for ca in [s.token_a_addr, s.token_b_addr, s.pool_addr]:
                w3.client.send_transaction_auto(
                    dk, ca, StepType.kContractGasPrefund, prefund=prefund_amount)
                time.sleep(0.05)

            time.sleep(2)  # wait for prefund consensus

            # Approve TokenA and TokenB for Pool
            approve_sel = func_selector("approve(address,uint256)")
            for token_addr in [s.token_a_addr, s.token_b_addr]:
                input_data = encode_call(approve_sel,
                    ['address', 'uint256'],
                    [bytes.fromhex(s.pool_addr), initial_liquidity * 2])
                w3.client.send_transaction_auto(
                    dk, token_addr, StepType.kContractExcute, input_hex=input_data)
                time.sleep(0.05)

            time.sleep(2)  # wait for approve consensus

            # addLiquidity
            add_liq_sel = func_selector("addLiquidity(uint256,uint256)")
            input_data = encode_call(add_liq_sel,
                ['uint256', 'uint256'],
                [initial_liquidity, initial_liquidity])
            w3.client.send_transaction_auto(
                dk, s.pool_addr, StepType.kContractExcute, input_hex=input_data)

        except Exception as e:
            print(f"  ✗ Set {i} liquidity failed: {e}")
            s.ok = False

        if (i + 1) % 5 == 0:
            print(f"  Liquidity setup: {i+1}/{len(ok_sets)}")

    ok_sets = [s for s in amm_sets if s.ok]
    print(f"  ✓ Liquidity done for {len(ok_sets)} sets")

    print(f"  Waiting 10s for liquidity consensus...")
    time.sleep(10)

    # ── Phase 6: Pair users + prefund + approve ──────────────────────────
    print(f"\n[Phase 6] Pairing users and setting up for swaps...")
    confirmed_users = [(pk, addr) for pk, addr in users
                       if w3.client.get_balance(addr) > 0]
    pair_count = min(len(confirmed_users) // 2, len(ok_sets))
    print(f"  Confirmed users: {len(confirmed_users)}, pairs: {pair_count}")

    swap_amount = 100
    token_transfer = swap_amount * stress_rounds + 1000

    pairs = []
    for p in range(pair_count):
        ua_pk, ua_addr = confirmed_users[p * 2]
        ub_pk, ub_addr = confirmed_users[p * 2 + 1]
        pool = ok_sets[p % len(ok_sets)]
        pairs.append((ua_pk, ua_addr, ub_pk, ub_addr, pool))

    # User prefund + deployer transfer tokens + user approve
    for pi, (ua_pk, ua_addr, ub_pk, ub_addr, pool) in enumerate(pairs):
        dk = pool.deployer_key
        try:
            # Prefund for both users on all 3 contracts
            for uk in [ua_pk, ub_pk]:
                for ca in [pool.token_a_addr, pool.token_b_addr, pool.pool_addr]:
                    w3.client.send_transaction_auto(
                        uk, ca, StepType.kContractGasPrefund, prefund=500_000_000)
                    time.sleep(0.02)

            time.sleep(1)

            # Deployer transfers tokens to users
            transfer_sel = func_selector("transfer(address,uint256)")
            # UserA gets TokenA, UserB gets TokenB
            input_a = encode_call(transfer_sel, ['address', 'uint256'],
                                  [bytes.fromhex(ua_addr), token_transfer])
            w3.client.send_transaction_auto(
                dk, pool.token_a_addr, StepType.kContractExcute, input_hex=input_a)

            input_b = encode_call(transfer_sel, ['address', 'uint256'],
                                  [bytes.fromhex(ub_addr), token_transfer])
            w3.client.send_transaction_auto(
                dk, pool.token_b_addr, StepType.kContractExcute, input_hex=input_b)

            time.sleep(1)

            # Users approve pool to spend their tokens
            approve_sel = func_selector("approve(address,uint256)")
            input_approve = encode_call(approve_sel, ['address', 'uint256'],
                                        [bytes.fromhex(pool.pool_addr), token_transfer])
            w3.client.send_transaction_auto(
                ua_pk, pool.token_a_addr, StepType.kContractExcute, input_hex=input_approve)
            w3.client.send_transaction_auto(
                ub_pk, pool.token_b_addr, StepType.kContractExcute, input_hex=input_approve)

        except Exception as e:
            print(f"  ✗ Pair {pi} setup failed: {e}")

        if (pi + 1) % 10 == 0:
            print(f"  Pair setup: {pi+1}/{pair_count}")

    print(f"  ✓ {pair_count} pairs set up")
    print(f"  Waiting 10s for setup consensus...")
    time.sleep(10)

    # ── Phase 7: Swap stress test ────────────────────────────────────────
    print(f"\n[Phase 7] Running swap stress test...")
    print(f"  {pair_count} pairs x {stress_rounds} rounds = {pair_count * stress_rounds * 2} swaps")

    swap_ok = 0
    swap_fail = 0
    lock = threading.Lock()
    stress_start = time.time()

    swap_a_sel = func_selector("swapAForB(uint256,uint256)")
    swap_b_sel = func_selector("swapBForA(uint256,uint256)")

    def swap_worker(pair_idx: int):
        nonlocal swap_ok, swap_fail
        ua_pk, ua_addr, ub_pk, ub_addr, pool = pairs[pair_idx]
        local_ok, local_fail = 0, 0

        for r in range(stress_rounds):
            try:
                # UserA swaps A→B
                input_a = encode_call(swap_a_sel, ['uint256', 'uint256'],
                                      [swap_amount, 0])
                w3.client.send_transaction_auto(
                    ua_pk, pool.pool_addr, StepType.kContractExcute, input_hex=input_a)
                local_ok += 1

                # UserB swaps B→A
                input_b = encode_call(swap_b_sel, ['uint256', 'uint256'],
                                      [swap_amount, 0])
                w3.client.send_transaction_auto(
                    ub_pk, pool.pool_addr, StepType.kContractExcute, input_hex=input_b)
                local_ok += 1

            except Exception:
                local_fail += 2

            time.sleep(0.05)

        with lock:
            swap_ok += local_ok
            swap_fail += local_fail

    with ThreadPoolExecutor(max_workers=min(16, pair_count)) as executor:
        futures = [executor.submit(swap_worker, i) for i in range(pair_count)]

        # Progress monitor
        while not all(f.done() for f in futures):
            time.sleep(3)
            elapsed = time.time() - stress_start
            with lock:
                total = swap_ok + swap_fail
            tps = total / elapsed if elapsed > 0 else 0
            print(f"  [{int(elapsed)}s] swaps: {total} (ok={swap_ok}, fail={swap_fail}) TPS={tps:.0f}")

        for f in futures:
            f.result()  # raise any exceptions

    elapsed = time.time() - stress_start
    total = swap_ok + swap_fail
    tps = total / elapsed if elapsed > 0 else 0

    # ── Results ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  AMM Contract Stress Test Results")
    print(f"{'='*70}")
    print(f"  Contract Sets: {len(ok_sets)}/{contract_sets}")
    print(f"  Trade Pairs:   {pair_count}")
    print(f"  Total Swaps:   {total}")
    print(f"  OK:            {swap_ok}")
    print(f"  Failed:        {swap_fail}")
    print(f"  Duration:      {elapsed:.1f}s")
    print(f"  TPS:           {tps:.0f}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
