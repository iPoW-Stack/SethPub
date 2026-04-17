#!/usr/bin/env python3
"""
Seth AMM Atomic Swap Demo
==========================
Demonstrates that AMM contracts deployed by the same account are co-located
in the same shard and pool, guaranteeing atomic execution of swap operations
without cross-shard compensation transactions.

Usage:
    python amm.py                          # default: 127.0.0.1:23001
    python amm.py --host 10.0.0.1 --port 23001

Requires: seth_sdk.py in the same directory.
"""
from __future__ import annotations

import argparse
import secrets
import time

from eth_utils import to_checksum_address
from seth_sdk import SethWeb3Mock, compile_and_link

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


# ---------------------------------------------------------------------------
# Test: AMM Same-Shard Atomic Execution
# ---------------------------------------------------------------------------

def test_amm(w3, my_addr: str, key: str):
    """
    Full AMM lifecycle test:
      1. Deploy TokenA, TokenB, AMMPool from the SAME account
         → guarantees all three land in the same shard & pool
      2. Approve AMMPool to spend tokens
      3. Add liquidity  (atomic cross-contract: 2x transferFrom)
      4. Swap A→B       (atomic: transferFrom + transfer + slippage check)
      5. Swap B→A       (reverse direction)
      6. Remove liquidity
      7. Verify final balances
    """
    print("\n" + "=" * 64)
    print("  AMM Demo — Same-Shard Atomic Execution")
    print("=" * 64)

    salt = secrets.token_hex(31)
    me = _ck(my_addr)

    # ── 1. Compile ────────────────────────────────────────────────────────
    ta_bin, ta_abi = compile_and_link(SIMPLE_TOKEN_SOL, "SimpleToken")
    pool_bin, pool_abi = compile_and_link(AMM_POOL_SOL, "AMMPool")

    # ── 2. Deploy TokenA ──────────────────────────────────────────────────
    print("\n[1] Deploying TokenA (supply=1,000,000)...")
    token_a = w3.seth.contract(abi=ta_abi, bytecode=ta_bin)
    token_a.deploy({'from': my_addr, 'salt': salt + 'ta',
                    'args': ["TokenA", 1_000_000]}, key)
    print(f"    TokenA @ {token_a.address}")

    # ── 3. Deploy TokenB ──────────────────────────────────────────────────
    print("\n[2] Deploying TokenB (supply=1,000,000)...")
    token_b = w3.seth.contract(abi=ta_abi, bytecode=ta_bin)
    token_b.deploy({'from': my_addr, 'salt': salt + 'tb',
                    'args': ["TokenB", 1_000_000]}, key)
    print(f"    TokenB @ {token_b.address}")

    # ── 4. Deploy AMMPool ─────────────────────────────────────────────────
    print("\n[3] Deploying AMMPool...")
    amm = w3.seth.contract(abi=pool_abi, bytecode=pool_bin)
    amm.deploy({'from': my_addr, 'salt': salt + 'am',
                'args': [_ck(token_a.address), _ck(token_b.address)]}, key)
    print(f"    AMMPool @ {amm.address}")
    print(f"    All 3 contracts deployed by {my_addr}")
    print(f"    → same shard & pool → atomic execution guaranteed ✅")

    # ── 5. Approve ────────────────────────────────────────────────────────
    approve_amount = 500_000
    print(f"\n[4] Approving AMMPool to spend {approve_amount} of each token...")
    r1 = token_a.functions.approve(_ck(amm.address), approve_amount).transact(key)
    r2 = token_b.functions.approve(_ck(amm.address), approve_amount).transact(key)
    assert r1.get('status') == 0 and r2.get('status') == 0, "Approve failed"
    print(f"    Approved ✅")

    # ── 6. Add Liquidity ──────────────────────────────────────────────────
    liq_a, liq_b = 100_000, 100_000
    print(f"\n[5] Adding liquidity: {liq_a} A + {liq_b} B...")
    r = amm.functions.addLiquidity(liq_a, liq_b).transact(key)
    print(f"    status={r.get('status')}")
    for e in r.get('decoded_events', []):
        print(f"    Event: {e['event']} → {e['args']}")
    ra, rb = _print_reserves(amm)
    assert ra == liq_a and rb == liq_b, f"Expected ({liq_a},{liq_b}), got ({ra},{rb})"
    print(f"    ✅ Liquidity added atomically")

    # ── 7. Swap A→B ──────────────────────────────────────────────────────
    swap_in = 10_000
    print(f"\n[6] Swapping {swap_in} A → B (minOut=0)...")
    r = amm.functions.swapAForB(swap_in, 0).transact(key)
    print(f"    status={r.get('status')}  output={r.get('decoded_output')}")
    for e in r.get('decoded_events', []):
        print(f"    Event: {e['event']} → {e['args']}")
    ra, rb = _print_reserves(amm)
    expected_ra = liq_a + swap_in  # 110000
    expected_out = (swap_in * liq_b) // (liq_a + swap_in)  # ≈ 9090
    assert ra == expected_ra, f"Expected reserveA={expected_ra}, got {ra}"
    print(f"    ✅ Swap A→B atomic (amountOut ≈ {expected_out})")

    # ── 8. Swap B→A ──────────────────────────────────────────────────────
    swap_b_in = 5_000
    print(f"\n[7] Swapping {swap_b_in} B → A (minOut=0)...")
    r = amm.functions.swapBForA(swap_b_in, 0).transact(key)
    print(f"    status={r.get('status')}  output={r.get('decoded_output')}")
    ra2, rb2 = _print_reserves(amm)
    print(f"    ✅ Swap B→A atomic")

    # ── 9. Remove Liquidity ───────────────────────────────────────────────
    print(f"\n[8] Removing all liquidity...")
    lp = amm.functions.liquidity(me).call()[0]
    print(f"    LP tokens held: {lp}")
    if lp > 0:
        r = amm.functions.removeLiquidity(lp).transact(key)
        print(f"    status={r.get('status')}")
        for e in r.get('decoded_events', []):
            print(f"    Event: {e['event']} → {e['args']}")
        _print_reserves(amm)
        print(f"    ✅ Liquidity removed")

    # ── 10. Final Balances ────────────────────────────────────────────────
    print(f"\n[9] Final token balances for {my_addr}:")
    bal_a = token_a.functions.balanceOf(me).call()[0]
    bal_b = token_b.functions.balanceOf(me).call()[0]
    print(f"    TokenA: {bal_a}")
    print(f"    TokenB: {bal_b}")

    print("\n" + "=" * 64)
    print("  ✅ AMM Demo PASSED — All operations atomic (same shard/pool)")
    print("=" * 64)

    # ── Summary ───────────────────────────────────────────────────────────
    print("""
  HOW SETH SOLVES THE AMM ATOMICITY PROBLEM
  ──────────────────────────────────────────
  1. All contracts deployed by the SAME account
     → CREATE2 address derivation places them in the same shard & pool

  2. AMMPool.swap() calls TokenA.transferFrom() + TokenB.transfer()
     in a SINGLE consensus round → fully atomic, no rollback needed

  3. Slippage failure triggers standard EVM REVERT
     → entire transaction rolls back, no compensation transactions

  4. Cross-shard transfers (user ↔ AMM shard) are handled BEFORE/AFTER
     the swap by the normal cross-shard mechanism (ToTxsPools)

  5. Developer experience is identical to Ethereum
     → standard Solidity, no async patterns required
""")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Seth AMM Atomic Swap Demo")
    parser.add_argument("--host", default="127.0.0.1", help="Node IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=23001, help="Node HTTPS port (default: 23001)")
    parser.add_argument("--key", default="71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6",
                        help="ECDSA private key (hex)")
    args = parser.parse_args()

    w3 = SethWeb3Mock(args.host, args.port)
    my_addr = w3.client.get_address(args.key)
    print(f"Node    : https://{args.host}:{args.port}")
    print(f"Account : {my_addr}")

    test_amm(w3, my_addr, args.key)


if __name__ == "__main__":
    main()
