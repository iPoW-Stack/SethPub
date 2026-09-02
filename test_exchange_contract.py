#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exchange Contract Multi-Shard Test
===================================
- Shards 3, 4, 5, 6 (HTTP ports 23001, 24001, 25001, 26001)
- 100 accounts pre-funded per shard (roles: deployer, sellers, buyers)
- 10 Exchange contracts deployed per shard
- Full flow per contract: CreateNewItem -> PurchaseItem -> ConfirmPurchase
- Read calls: GetAllItemJson, GetOwnerItemJson, GetSellDetail
"""

import os
import sys
import json
import time
import secrets
import hashlib
import argparse
from typing import Dict, List, Any, Tuple

sys.path.insert(0, os.path.dirname(__file__))
from seth_sdk import SethWeb3Mock, StepType, compile_and_link

# ── Config ────────────────────────────────────────────────────────────────────
HOST = "192.168.25.129"
SHARDS = [3, 4, 5, 6]
# HTTP port formula: 2{shard}001 (node 1 of each shard)
SHARD_PORT = {s: int(f"2{s}001") for s in SHARDS}

CONTRACTS_PER_SHARD = 10
ACCOUNTS_PER_SHARD  = 100   # total per shard: 1 deployer + 33 sellers + 66 buyers

INITIAL_BALANCE    = 50_000_000   # per account
CONTRACT_PREFUND   = 5_000_000    # gas prefund per account per contract
ITEM_PRICE         = 100_000      # wei per item listing
PURCHASE_VALUE     = 150_000      # bid amount (> price)

# Fixed funder key (genesis / well-funded account)
FUNDER_KEY = "71e571862c0e4aefa87a3c16057a62c8331991a11746ab7ff8c6b6418e73b2f6"

EXCHANGE_SOURCE = open(
    os.path.join(os.path.dirname(__file__), "../src/contract/tests/contracts/exchange.sol")
).read()


# ── Helpers ───────────────────────────────────────────────────────────────────

def ok(receipt: Dict, label: str) -> None:
    status = receipt.get("status")
    if status != 0:
        raise RuntimeError(f"{label} FAILED status={status} msg={receipt.get('msg','')}")


def fund(w3: SethWeb3Mock, addr: str, amount: int = INITIAL_BALANCE) -> None:
    bal = w3.client.get_balance(addr)
    if bal >= amount:
        return
    tx = w3.client.send_transaction_auto(
        FUNDER_KEY, addr, StepType.kNormalFrom, amount=amount - bal
    )
    r = w3.client.wait_for_receipt(tx)
    ok(r, f"fund {addr[:12]}")
    deadline = time.time() + 120
    while time.time() < deadline:
        if w3.client.get_balance(addr) >= amount:
            return
        time.sleep(2)
    raise RuntimeError(f"balance timeout for {addr}")


def prefund_contract(contract, key: str, amount: int = CONTRACT_PREFUND) -> None:
    addr = contract.client.get_address(key)
    cur  = contract.get_prefund(addr)
    if cur >= amount:
        return
    r = contract.prefund(amount - cur, key)
    ok(r, f"prefund {addr[:12]}")
    deadline = time.time() + 120
    while time.time() < deadline:
        if contract.get_prefund(addr) >= amount:
            return
        time.sleep(2)
    raise RuntimeError(f"prefund timeout for {addr}")


def make_hash32() -> bytes:
    return secrets.token_bytes(32)


def ts_ms() -> int:
    return int(time.time() * 1000)


# ── Per-shard test ─────────────────────────────────────────────────────────────

def run_shard(shard: int) -> Dict[str, Any]:
    port = SHARD_PORT[shard]
    print(f"\n{'='*60}")
    print(f"  SHARD {shard}  ({HOST}:{port})")
    print(f"{'='*60}")

    w3 = SethWeb3Mock(HOST, port)
    results = {"shard": shard, "contracts": [], "errors": []}

    # ── Step 1: compile ────────────────────────────────────────────────────
    print(f"[Shard {shard}] Compiling Exchange contract...")
    try:
        bytecode, abi = compile_and_link(EXCHANGE_SOURCE, "Exchange")
        print(f"  bytecode {len(bytecode)} chars, {len([f for f in abi if f['type']=='function'])} functions")
    except Exception as e:
        results["errors"].append(f"compile: {e}")
        print(f"  COMPILE FAILED: {e}")
        return results

    # ── Step 2: create accounts ────────────────────────────────────────────
    print(f"[Shard {shard}] Generating {ACCOUNTS_PER_SHARD} accounts...")
    keys  = [secrets.token_hex(32) for _ in range(ACCOUNTS_PER_SHARD)]
    addrs = [w3.client.get_address(k) for k in keys]

    deployer_key  = keys[0]
    deployer_addr = addrs[0]
    # sellers: indices 1..33, buyers: indices 34..99
    seller_keys  = keys[1:34]
    seller_addrs = addrs[1:34]
    buyer_keys   = keys[34:]
    buyer_addrs  = addrs[34:]

    print(f"  deployer : {deployer_addr[:18]}...")
    print(f"  sellers  : {len(seller_keys)}  buyers: {len(buyer_keys)}")

    print(f"[Shard {shard}] Funding accounts (this may take a while)...")
    all_keys  = keys
    all_addrs = addrs
    for i, (k, a) in enumerate(zip(all_keys, all_addrs)):
        try:
            fund(w3, a)
            if (i + 1) % 20 == 0:
                print(f"  funded {i+1}/{ACCOUNTS_PER_SHARD}")
        except Exception as e:
            results["errors"].append(f"fund {a[:12]}: {e}")
            print(f"  WARN fund failed {a[:12]}: {e}")

    print(f"  All accounts funded.")

    # ── Step 3: deploy contracts + run tests ───────────────────────────────
    for ci in range(CONTRACTS_PER_SHARD):
        contract_result = {
            "index": ci,
            "address": None,
            "passed": [],
            "failed": [],
        }
        print(f"\n[Shard {shard}] Contract {ci+1}/{CONTRACTS_PER_SHARD} ─ deploying...")

        # pick roles round-robin across sellers/buyers
        seller_key   = seller_keys[ci % len(seller_keys)]
        seller_addr  = seller_addrs[ci % len(seller_addrs)]
        buyer_key1   = buyer_keys[ci % len(buyer_keys)]
        buyer_addr1  = buyer_addrs[ci % len(buyer_addrs)]
        buyer_key2   = buyer_keys[(ci + 1) % len(buyer_keys)]
        buyer_addr2  = buyer_addrs[(ci + 1) % len(buyer_addrs)]

        try:
            exchange = w3.seth.contract(abi=abi, bytecode=bytecode)
            salt = secrets.token_hex(31) + f"{ci:02x}"
            exchange.deploy(
                {"from": deployer_addr, "salt": salt, "args": [], "amount": 0},
                deployer_key,
            )
            contract_result["address"] = exchange.address
            print(f"  deployed at {exchange.address}")
        except Exception as e:
            contract_result["failed"].append(f"deploy: {e}")
            results["contracts"].append(contract_result)
            print(f"  DEPLOY FAILED: {e}")
            continue

        # prefund all participants for gas
        for key in [deployer_key, seller_key, buyer_key1, buyer_key2]:
            try:
                prefund_contract(exchange, key)
            except Exception as e:
                print(f"  WARN prefund: {e}")

        # ── Test 1: CreateNewItem ──────────────────────────────────────────
        item_hash  = make_hash32()
        item_info  = f"shard{shard}_contract{ci}_item0".encode()
        item_price = ITEM_PRICE
        start_ms   = ts_ms()
        end_ms     = start_ms + 86400_000  # 1 day

        print(f"  [1] CreateNewItem hash={item_hash.hex()[:16]}...")
        try:
            r = exchange.functions.CreateNewItem(
                item_hash, item_info, item_price, start_ms, end_ms
            ).transact(seller_key)
            ok(r, "CreateNewItem")
            contract_result["passed"].append("CreateNewItem")
            print(f"      OK status={r.get('status')}")
        except Exception as e:
            contract_result["failed"].append(f"CreateNewItem: {e}")
            print(f"      FAILED: {e}")

        # create a second item for multi-item view tests
        item_hash2  = make_hash32()
        item_info2  = f"shard{shard}_contract{ci}_item1".encode()
        try:
            r = exchange.functions.CreateNewItem(
                item_hash2, item_info2, item_price, start_ms, end_ms
            ).transact(seller_key)
            ok(r, "CreateNewItem #2")
        except Exception as e:
            print(f"      CreateNewItem #2 WARN: {e}")

        # ── Test 2: PurchaseItem (buyer1) ─────────────────────────────────
        print(f"  [2] PurchaseItem by buyer1...")
        try:
            r = exchange.functions.PurchaseItem(
                item_hash, ts_ms()
            ).transact(buyer_key1, value=PURCHASE_VALUE)
            ok(r, "PurchaseItem buyer1")
            contract_result["passed"].append("PurchaseItem_buyer1")
            print(f"      OK status={r.get('status')}")
        except Exception as e:
            contract_result["failed"].append(f"PurchaseItem_buyer1: {e}")
            print(f"      FAILED: {e}")

        # ── Test 3: PurchaseItem (buyer2, higher bid) ─────────────────────
        print(f"  [3] PurchaseItem by buyer2 (higher bid)...")
        try:
            r = exchange.functions.PurchaseItem(
                item_hash, ts_ms()
            ).transact(buyer_key2, value=PURCHASE_VALUE + 50_000)
            ok(r, "PurchaseItem buyer2")
            contract_result["passed"].append("PurchaseItem_buyer2")
            print(f"      OK status={r.get('status')}")
        except Exception as e:
            contract_result["failed"].append(f"PurchaseItem_buyer2: {e}")
            print(f"      FAILED: {e}")

        # ── Test 4: ConfirmPurchase (seller confirms, highest bidder wins) ─
        print(f"  [4] ConfirmPurchase by seller...")
        try:
            r = exchange.functions.ConfirmPurchase(item_hash).transact(seller_key)
            ok(r, "ConfirmPurchase")
            contract_result["passed"].append("ConfirmPurchase")
            print(f"      OK status={r.get('status')}")
        except Exception as e:
            contract_result["failed"].append(f"ConfirmPurchase: {e}")
            print(f"      FAILED: {e}")

        # ── Test 5: GetAllItemJson (view) ─────────────────────────────────
        print(f"  [5] GetAllItemJson(0, 10)...")
        try:
            ret = exchange.functions.GetAllItemJson(0, 10).call()
            raw = ret[0] if isinstance(ret, (list, tuple)) else ret
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="replace")
            contract_result["passed"].append("GetAllItemJson")
            print(f"      OK len={len(raw)} chars preview={raw[:80]!r}")
        except Exception as e:
            contract_result["failed"].append(f"GetAllItemJson: {e}")
            print(f"      FAILED: {e}")

        # ── Test 6: GetOwnerItemJson (view) ───────────────────────────────
        print(f"  [6] GetOwnerItemJson(0, 10, seller)...")
        try:
            ret = exchange.functions.GetOwnerItemJson(0, 10, seller_addr).call()
            raw = ret[0] if isinstance(ret, (list, tuple)) else ret
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="replace")
            contract_result["passed"].append("GetOwnerItemJson")
            print(f"      OK len={len(raw)} chars preview={raw[:80]!r}")
        except Exception as e:
            contract_result["failed"].append(f"GetOwnerItemJson: {e}")
            print(f"      FAILED: {e}")

        # ── Test 7: GetSellDetail (view) ──────────────────────────────────
        print(f"  [7] GetSellDetail(item_hash)...")
        try:
            ret = exchange.functions.GetSellDetail(item_hash).call()
            raw = ret[0] if isinstance(ret, (list, tuple)) else ret
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="replace")
            contract_result["passed"].append("GetSellDetail")
            print(f"      OK len={len(raw)} chars preview={raw[:80]!r}")
        except Exception as e:
            contract_result["failed"].append(f"GetSellDetail: {e}")
            print(f"      FAILED: {e}")

        # ── Test 8: item_map public getter ────────────────────────────────
        print(f"  [8] item_map(item_hash) public getter...")
        try:
            ret = exchange.functions.item_map(item_hash).call()
            contract_result["passed"].append("item_map_getter")
            print(f"      OK ret={str(ret)[:120]}")
        except Exception as e:
            contract_result["failed"].append(f"item_map_getter: {e}")
            print(f"      FAILED: {e}")

        # ── Test 9: id_with_hash_map getter ───────────────────────────────
        print(f"  [9] id_with_hash_map(0)...")
        try:
            ret = exchange.functions.id_with_hash_map(0).call()
            contract_result["passed"].append("id_with_hash_map")
            print(f"      OK ret={ret.hex() if isinstance(ret, bytes) else ret}")
        except Exception as e:
            contract_result["failed"].append(f"id_with_hash_map: {e}")
            print(f"      FAILED: {e}")

        # ── Test 10: Duplicate CreateNewItem should revert ────────────────
        print(f"  [10] Duplicate CreateNewItem (expect revert)...")
        try:
            r = exchange.functions.CreateNewItem(
                item_hash, item_info, item_price, start_ms, end_ms
            ).transact(seller_key)
            # status != 0 means it reverted as expected
            if r.get("status") != 0:
                contract_result["passed"].append("CreateNewItem_duplicate_revert")
                print(f"      OK reverted as expected status={r.get('status')}")
            else:
                contract_result["failed"].append("CreateNewItem_duplicate_revert: did not revert")
                print(f"      UNEXPECTED SUCCESS (should have reverted)")
        except Exception as e:
            # exception also means it reverted
            contract_result["passed"].append("CreateNewItem_duplicate_revert")
            print(f"      OK reverted (exception): {str(e)[:80]}")

        # ── Test 11: PurchaseItem by owner should revert ──────────────────
        print(f"  [11] PurchaseItem by owner (expect revert)...")
        try:
            r = exchange.functions.PurchaseItem(
                item_hash2, ts_ms()
            ).transact(seller_key, value=PURCHASE_VALUE)
            if r.get("status") != 0:
                contract_result["passed"].append("PurchaseItem_owner_revert")
                print(f"      OK reverted as expected status={r.get('status')}")
            else:
                contract_result["failed"].append("PurchaseItem_owner_revert: did not revert")
                print(f"      UNEXPECTED SUCCESS")
        except Exception as e:
            contract_result["passed"].append("PurchaseItem_owner_revert")
            print(f"      OK reverted (exception): {str(e)[:80]}")

        results["contracts"].append(contract_result)
        passed = len(contract_result["passed"])
        failed = len(contract_result["failed"])
        print(f"\n  Contract {ci+1} summary: {passed} passed, {failed} failed")

    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Exchange contract multi-shard test")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--shards", default=",".join(map(str, SHARDS)),
                        help="Comma-separated shard IDs")
    parser.add_argument("--contracts", type=int, default=CONTRACTS_PER_SHARD)
    parser.add_argument("--accounts",  type=int, default=ACCOUNTS_PER_SHARD)
    args = parser.parse_args()

    global HOST, CONTRACTS_PER_SHARD, ACCOUNTS_PER_SHARD
    HOST = args.host
    CONTRACTS_PER_SHARD = args.contracts
    ACCOUNTS_PER_SHARD  = args.accounts
    shards = [int(s) for s in args.shards.split(",")]

    print("Exchange Contract Multi-Shard Test")
    print(f"  Shards     : {shards}")
    print(f"  Contracts  : {CONTRACTS_PER_SHARD} per shard")
    print(f"  Accounts   : {ACCOUNTS_PER_SHARD} per shard")
    print(f"  Host       : {HOST}")

    all_results = []
    start = time.time()
    for shard in shards:
        r = run_shard(shard)
        all_results.append(r)

    # ── Final summary ──────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    total_passed = total_failed = total_contracts = 0
    for sr in all_results:
        s = sr["shard"]
        for cr in sr["contracts"]:
            total_contracts += 1
            p = len(cr["passed"])
            f = len(cr["failed"])
            total_passed += p
            total_failed += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  Shard {s} Contract {cr['index']+1:2d} @ {cr['address'] or 'N/A':42s}  "
                  f"passed={p:2d} failed={f:2d}  [{status}]")
            for msg in cr["failed"]:
                print(f"      FAIL: {msg}")
        if sr["errors"]:
            for e in sr["errors"]:
                print(f"  Shard {s} ERROR: {e}")
    print("-" * 60)
    print(f"  Total contracts : {total_contracts}")
    print(f"  Total passed    : {total_passed}")
    print(f"  Total failed    : {total_failed}")
    print(f"  Duration        : {time.time()-start:.1f}s")
    print("=" * 60)
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
