#!/usr/bin/env python3
"""
Seth AMM Multi-User Atomic Swap Demo
======================================
Demonstrates that:
  1. AMM contracts deployed by the SAME account are co-located in the same
     shard & pool, guaranteeing atomic execution.
  2. DIFFERENT users (separate private keys) can interact with the AMM —
     each user sets prefund, approves tokens, swaps, and refunds.

This is a realistic scenario: one deployer creates the DeFi protocol,
multiple independent users trade on it.

Usage:
    python amm.py                              # default: 127.0.0.1:23001
    python amm.py --host 10.0.0.1 --port 23001
    python amm.py --users 3                    # number of trader accounts

Requires: seth_sdk.py in the same directory.
"""
from __future__ import annotations

import argparse
import secrets
import time

from eth_utils import to_checksum_address
from seth_sdk import SethWeb3Mock, StepType, compile_and_link

# ---------------------------------------------------------------------------
# Solidity Sources
# ---------------------------------------------------------------------------

SIMPLE_TOKEN_SOL = """
pragma solidity ^0.8.0;

contract SimpleToken {
    string  public name;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, uint256 _initialSupply) {
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
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB);
    event Swap(address indexed user, address tokenIn, uint256 amountIn, uint256 amountOut);

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 lp) {
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
        if (totalLiquidity == 0) {
            lp = amountA;
        } else {
            lp = (amountA * totalLiquidity) / reserveA;
        }
        reserveA += amountA;
        reserveB += amountB;
        totalLiquidity += lp;
        liquidity[msg.sender] += lp;
        emit LiquidityAdded(msg.sender, amountA, amountB, lp);
    }

    function removeLiquidity(uint256 lpAmount) external {
        require(liquidity[msg.sender] >= lpAmount, "insufficient lp");
        uint256 amountA = (lpAmount * reserveA) / totalLiquidity;
        uint256 amountB = (lpAmount * reserveB) / totalLiquidity;
        liquidity[msg.sender] -= lpAmount;
        totalLiquidity -= lpAmount;
        reserveA -= amountA;
        reserveB -= amountB;
        tokenA.transfer(msg.sender, amountA);
        tokenB.transfer(msg.sender, amountB);
        emit LiquidityRemoved(msg.sender, amountA, amountB);
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ck(addr: str) -> str:
    """Shorthand for checksum address."""
    return to_checksum_address("0x" + addr.replace("0x", ""))


def _print_reserves(amm):
    r = amm.functions.getReserves().call()
    print(f"    Reserves: A={r[0]}, B={r[1]}")
    return r


def _wait_balance(token, addr_ck, expected, label="", retries=30):
    """Poll token balance until it matches expected value."""
    for i in range(retries):
        bal = token.functions.balanceOf(addr_ck).call()[0]
        if bal == expected:
            return bal
        time.sleep(2)
    bal = token.functions.balanceOf(addr_ck).call()[0]
    return bal


def _wait_prefund(contract, user_addr, expected, label="", retries=30):
    """Poll prefund balance until it reaches at least the expected value."""
    for i in range(retries):
        pf = contract.get_prefund(user_addr)
        if pf >= expected:
            return pf
        time.sleep(2)
    pf = contract.get_prefund(user_addr)
    return pf


def _wait_account_exists(client, addr, label="", retries=30):
    """Poll until the account address is queryable (balance >= 0 and no error)."""
    for i in range(retries):
        try:
            bal = client.get_balance(addr)
            if bal >= 0:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


# ---------------------------------------------------------------------------
# Test: Multi-User AMM
# ---------------------------------------------------------------------------

def test_amm(w3, deployer_addr: str, deployer_key: str, num_users: int = 3):
    """
    Multi-user AMM lifecycle:

    Phase 1 — Deployer sets up the protocol
      1. Deploy TokenA, TokenB, AMMPool from ONE account (same shard/pool)
      2. Add initial liquidity

    Phase 2 — Create trader accounts
      3. Generate N new private keys (independent users)
      4. Deployer transfers tokens to each user
      5. Each user sets prefund on TokenA, TokenB, AMMPool contracts

    Phase 3 — Users trade
      6. Each user approves AMMPool and executes swaps
      7. Verify reserves and balances after each swap

    Phase 4 — Cleanup
      8. Each user refunds prefund from all contracts
    """
    print("\n" + "=" * 64)
    print("  AMM Multi-User Demo — Same-Shard Atomic Execution")
    print("=" * 64)

    salt = secrets.token_hex(31)
    deployer_ck = _ck(deployer_addr)

    # ══════════════════════════════════════════════════════════════════════
    # Phase 1: Deployer sets up the protocol
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 64)
    print("  Phase 1: Deploy Protocol (single deployer → same shard/pool)")
    print("─" * 64)

    ta_bin, ta_abi = compile_and_link(SIMPLE_TOKEN_SOL, "SimpleToken")
    pool_bin, pool_abi = compile_and_link(AMM_POOL_SOL, "AMMPool")

    # Deploy TokenA
    print("\n[1] Deploying TokenA (supply=10,000,000)...")
    token_a = w3.seth.contract(abi=ta_abi, bytecode=ta_bin)
    token_a.deploy({'from': deployer_addr, 'salt': salt + 'ta',
                    'args': ["TokenA", 10_000_000]}, deployer_key)
    print(f"    TokenA @ {token_a.address}")

    # Deploy TokenB
    print("\n[2] Deploying TokenB (supply=10,000,000)...")
    token_b = w3.seth.contract(abi=ta_abi, bytecode=ta_bin)
    token_b.deploy({'from': deployer_addr, 'salt': salt + 'tb',
                    'args': ["TokenB", 10_000_000]}, deployer_key)
    print(f"    TokenB @ {token_b.address}")

    # Deploy AMMPool
    print("\n[3] Deploying AMMPool...")
    amm = w3.seth.contract(abi=pool_abi, bytecode=pool_bin)
    amm.deploy({'from': deployer_addr, 'salt': salt + 'am',
                'args': [_ck(token_a.address), _ck(token_b.address)]}, deployer_key)
    print(f"    AMMPool @ {amm.address}")
    print(f"    Deployer: {deployer_addr}")
    print(f"    → All 3 contracts in same shard & pool ✅")

    # Deployer: prefund on all 3 contracts + approve + add liquidity
    prefund_amount = 50_000_000
    print(f"\n[4] Deployer: prefund {prefund_amount} on each contract...")
    token_a.prefund(prefund_amount, deployer_key)
    token_b.prefund(prefund_amount, deployer_key)
    amm.prefund(prefund_amount, deployer_key)

    # Verify deployer prefund
    print(f"    Verifying deployer prefund...")
    dpf_a = _wait_prefund(token_a, deployer_addr, prefund_amount, "Deployer TokenA")
    dpf_b = _wait_prefund(token_b, deployer_addr, prefund_amount, "Deployer TokenB")
    dpf_amm = _wait_prefund(amm, deployer_addr, prefund_amount, "Deployer AMMPool")
    print(f"    Prefund: TokenA={dpf_a}, TokenB={dpf_b}, AMMPool={dpf_amm}")
    assert dpf_a >= prefund_amount, f"Deployer TokenA prefund failed: {dpf_a}"
    assert dpf_b >= prefund_amount, f"Deployer TokenB prefund failed: {dpf_b}"
    assert dpf_amm >= prefund_amount, f"Deployer AMMPool prefund failed: {dpf_amm}"
    print(f"    ✅ Deployer prefund verified")

    print(f"\n[5] Deployer: approve AMMPool + add initial liquidity (500,000 each)...")
    token_a.functions.approve(_ck(amm.address), 500_000).transact(deployer_key)
    token_b.functions.approve(_ck(amm.address), 500_000).transact(deployer_key)
    r = amm.functions.addLiquidity(500_000, 500_000).transact(deployer_key)
    assert r.get('status') == 0, f"addLiquidity failed: {r}"
    ra, rb = _print_reserves(amm)
    assert ra == 500_000 and rb == 500_000
    print(f"    ✅ Initial liquidity: A={ra}, B={rb}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 2: Create independent trader accounts
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 64)
    print(f"  Phase 2: Create {num_users} Trader Accounts")
    print("─" * 64)

    users = []  # list of (addr, key, name)
    tokens_per_user = 100_000
    user_prefund = 10_000_000

    for i in range(num_users):
        user_key = secrets.token_hex(32)
        user_addr = w3.client.get_address(user_key)
        name = f"User_{i+1}"
        users.append((user_addr, user_key, name))
        user_ck = _ck(user_addr)
        print(f"\n[{name}] Address: {user_addr}")

        # ── Step A: Transfer tokens from deployer to user ─────────────
        print(f"    Deployer → {name}: {tokens_per_user} TokenA...")
        r = token_a.functions.transfer(user_ck, tokens_per_user).transact(deployer_key)
        assert r.get('status') == 0, f"Transfer TokenA to {name} failed"

        print(f"    Deployer → {name}: {tokens_per_user} TokenB...")
        r = token_b.functions.transfer(user_ck, tokens_per_user).transact(deployer_key)
        assert r.get('status') == 0, f"Transfer TokenB to {name} failed"

        # ── Step B: Verify user account exists and token balances ─────
        print(f"    Verifying {name} account exists...")
        exists = _wait_account_exists(w3.client, user_addr, name)
        assert exists, f"{name} account not found on chain!"
        print(f"    ✅ {name} account exists on chain")

        bal_a = _wait_balance(token_a, user_ck, tokens_per_user, f"{name} TokenA")
        bal_b = _wait_balance(token_b, user_ck, tokens_per_user, f"{name} TokenB")
        print(f"    Token balances: A={bal_a}, B={bal_b}")
        assert bal_a == tokens_per_user, \
            f"❌ {name} TokenA balance mismatch: expected {tokens_per_user}, got {bal_a}"
        assert bal_b == tokens_per_user, \
            f"❌ {name} TokenB balance mismatch: expected {tokens_per_user}, got {bal_b}"
        print(f"    ✅ Token balances verified")

        # ── Step C: User sets prefund on all 3 contracts ──────────────
        print(f"    {name}: prefund {user_prefund} on TokenA, TokenB, AMMPool...")
        token_a.prefund(user_prefund, user_key)
        token_b.prefund(user_prefund, user_key)
        amm.prefund(user_prefund, user_key)

        # ── Step D: Verify prefund balances ───────────────────────────
        print(f"    Verifying {name} prefund balances...")
        pf_a = _wait_prefund(token_a, user_addr, user_prefund, f"{name} TokenA prefund")
        pf_b = _wait_prefund(token_b, user_addr, user_prefund, f"{name} TokenB prefund")
        pf_amm = _wait_prefund(amm, user_addr, user_prefund, f"{name} AMMPool prefund")
        print(f"    Prefund: TokenA={pf_a}, TokenB={pf_b}, AMMPool={pf_amm}")
        assert pf_a >= user_prefund, \
            f"❌ {name} TokenA prefund mismatch: expected >={user_prefund}, got {pf_a}"
        assert pf_b >= user_prefund, \
            f"❌ {name} TokenB prefund mismatch: expected >={user_prefund}, got {pf_b}"
        assert pf_amm >= user_prefund, \
            f"❌ {name} AMMPool prefund mismatch: expected >={user_prefund}, got {pf_amm}"
        print(f"    ✅ Prefund verified — {name} ready to trade")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 3: Each user trades independently
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 64)
    print("  Phase 3: Multi-User Trading")
    print("─" * 64)

    for idx, (user_addr, user_key, name) in enumerate(users):
        user_ck = _ck(user_addr)
        print(f"\n{'─' * 40}")
        print(f"  {name} ({user_addr[:16]}...)")
        print(f"{'─' * 40}")

        # Create contract handles bound to this user's sender_address
        user_token_a = w3.seth.contract(address=token_a.address, abi=ta_abi,
                                        sender_address=user_addr)
        user_token_b = w3.seth.contract(address=token_b.address, abi=ta_abi,
                                        sender_address=user_addr)
        user_amm = w3.seth.contract(address=amm.address, abi=pool_abi,
                                    sender_address=user_addr)

        # Step A: Approve AMMPool to spend user's tokens
        approve_amt = 50_000
        print(f"\n  [A] {name}: approve AMMPool for {approve_amt} of each token...")
        r1 = user_token_a.functions.approve(_ck(amm.address), approve_amt).transact(user_key)
        r2 = user_token_b.functions.approve(_ck(amm.address), approve_amt).transact(user_key)
        assert r1.get('status') == 0, f"{name} approve TokenA failed: {r1}"
        assert r2.get('status') == 0, f"{name} approve TokenB failed: {r2}"
        print(f"      Approved ✅")

        # Step B: Swap A→B
        swap_a_in = 10_000 + idx * 5_000  # each user swaps a different amount
        print(f"\n  [B] {name}: swap {swap_a_in} A → B...")
        ra_before, rb_before = amm.functions.getReserves().call()
        expected_out = (swap_a_in * rb_before) // (ra_before + swap_a_in)

        r = user_amm.functions.swapAForB(swap_a_in, 0).transact(user_key)
        print(f"      status={r.get('status')}  output={r.get('decoded_output')}")
        for e in r.get('decoded_events', []):
            print(f"      Event: {e['event']} → {e['args']}")
        assert r.get('status') == 0, f"{name} swapAForB failed: {r}"
        ra_after, rb_after = _print_reserves(user_amm)
        assert ra_after == ra_before + swap_a_in, \
            f"reserveA mismatch: expected {ra_before + swap_a_in}, got {ra_after}"
        print(f"      ✅ Swap A→B atomic (in={swap_a_in}, out≈{expected_out})")

        # Step C: Swap B→A (reverse)
        swap_b_in = 3_000 + idx * 2_000
        print(f"\n  [C] {name}: swap {swap_b_in} B → A...")
        r = user_amm.functions.swapBForA(swap_b_in, 0).transact(user_key)
        print(f"      status={r.get('status')}  output={r.get('decoded_output')}")
        assert r.get('status') == 0, f"{name} swapBForA failed: {r}"
        _print_reserves(user_amm)
        print(f"      ✅ Swap B→A atomic")

        # Step D: Check user's final token balances
        bal_a = user_token_a.functions.balanceOf(user_ck).call()[0]
        bal_b = user_token_b.functions.balanceOf(user_ck).call()[0]
        print(f"\n  [D] {name} balances: TokenA={bal_a}, TokenB={bal_b}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 4: Cleanup — all users refund prefund
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 64)
    print("  Phase 4: Refund Prefund (all users + deployer)")
    print("─" * 64)

    for user_addr, user_key, name in users:
        print(f"\n  {name}: refunding prefund from TokenA, TokenB, AMMPool...")
        # Bind contract handles for refund
        c_a = w3.seth.contract(address=token_a.address, abi=ta_abi,
                               sender_address=user_addr)
        c_b = w3.seth.contract(address=token_b.address, abi=ta_abi,
                               sender_address=user_addr)
        c_amm = w3.seth.contract(address=amm.address, abi=pool_abi,
                                 sender_address=user_addr)
        c_a.refund(user_key)
        c_b.refund(user_key)
        c_amm.refund(user_key)
        print(f"    ✅ {name} refunded")

    # Deployer refund
    print(f"\n  Deployer: refunding prefund...")
    token_a.refund(deployer_key)
    token_b.refund(deployer_key)
    amm.refund(deployer_key)
    print(f"    ✅ Deployer refunded")

    # ══════════════════════════════════════════════════════════════════════
    # Final Summary
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 64)
    print("  Final State")
    print("─" * 64)
    ra, rb = _print_reserves(amm)
    print(f"\n  Deployer token balances:")
    print(f"    TokenA: {token_a.functions.balanceOf(deployer_ck).call()[0]}")
    print(f"    TokenB: {token_b.functions.balanceOf(deployer_ck).call()[0]}")
    for user_addr, user_key, name in users:
        user_ck = _ck(user_addr)
        ba = token_a.functions.balanceOf(user_ck).call()[0]
        bb = token_b.functions.balanceOf(user_ck).call()[0]
        print(f"  {name} ({user_addr[:12]}...): TokenA={ba}, TokenB={bb}")

    print("\n" + "=" * 64)
    print("  ✅ AMM Multi-User Demo PASSED")
    print("=" * 64)
    print("""
  KEY TAKEAWAYS
  ─────────────
  1. DEPLOYER creates all contracts from ONE account
     → TokenA, TokenB, AMMPool land in the same shard & pool

  2. MULTIPLE INDEPENDENT USERS interact with the AMM
     → Each user has their own private key and address
     → Each user sets prefund (gas deposit) on contracts
     → Each user approves and swaps independently

  3. EVERY SWAP IS ATOMIC within a single consensus round
     → AMMPool.swap() calls TokenA.transferFrom() + TokenB.transfer()
     → If slippage check fails → standard EVM REVERT, entire tx rolls back
     → No cross-shard coordination, no compensation transactions

  4. PREFUND / REFUND lifecycle
     → Users deposit gas prefund before interacting with contracts
     → After trading, users reclaim unused gas via refund
     → Clean resource management

  5. DEVELOPER EXPERIENCE = ETHEREUM
     → Standard Solidity contracts, standard ERC20 approve/transferFrom
     → No async patterns, no manual compensation logic
""")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Seth AMM Multi-User Atomic Swap Demo")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Node IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=23001,
                        help="Node HTTPS port (default: 23001)")
    parser.add_argument("--key",
                        default="71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6",
                        help="Deployer ECDSA private key (hex)")
    parser.add_argument("--users", type=int, default=3,
                        help="Number of trader accounts to create (default: 3)")
    args = parser.parse_args()

    w3 = SethWeb3Mock(args.host, args.port)
    deployer_addr = w3.client.get_address(args.key)
    print(f"Node     : https://{args.host}:{args.port}")
    print(f"Deployer : {deployer_addr}")
    print(f"Traders  : {args.users}")

    test_amm(w3, deployer_addr, args.key, num_users=args.users)


if __name__ == "__main__":
    main()
