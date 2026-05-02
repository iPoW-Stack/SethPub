#!/usr/bin/env python3
"""
Transfer Stress Test — Python equivalent of tx_cli.cc Mode 4

Phases:
  1. Generate N test accounts (random keypairs)
  2. Fund them from pre-existing funder accounts
  3. Batch-verify all accounts on chain
  4. Run random transfer stress test between accounts
  5. Report TPS

Usage:
  python3 test_transfer_stress.py <ip> <port> <funder_key> [account_count] [threads] [rounds] [tps]

Example:
  python3 test_transfer_stress.py 127.0.0.1 23001 7c5b4ec6...66 1000 8 5000 0
"""

from __future__ import annotations
import sys, os, time, secrets, struct, hashlib, random, json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from Crypto.Hash import keccak


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


def sign_and_send(base_url: str, pk_hex: str, to: str, amount: int,
                  nonce: int, step: int = 0, gas_limit: int = 210000,
                  gas_price: int = 1, prefund: int = 0,
                  contract_code: str = '', input_hex: str = '',
                  verify_ssl: bool = False) -> bool:
    """Build, sign, and POST a transaction. Returns True on HTTP 200."""
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed").hex()

    msg = bytearray()
    msg.extend(struct.pack('<Q', nonce))
    msg.extend(bytes.fromhex(pub))
    msg.extend(bytes.fromhex(to.replace('0x', '')))
    msg.extend(struct.pack('<Q', amount))
    msg.extend(struct.pack('<Q', gas_limit))
    msg.extend(struct.pack('<Q', gas_price))
    msg.extend(struct.pack('<Q', step))
    if contract_code:
        msg.extend(bytes.fromhex(contract_code))
    if input_hex:
        msg.extend(bytes.fromhex(input_hex))
    if prefund > 0:
        msg.extend(struct.pack('<Q', prefund))

    txh = keccak256(bytes(msg))
    sig = sk.sign_digest_deterministic(txh, hashfunc=hashlib.sha256,
                                       sigencode=sigencode_string_canonize)

    data = {
        "nonce": str(nonce), "pubkey": pub, "to": to,
        "amount": str(amount), "gas_limit": str(gas_limit),
        "gas_price": str(gas_price), "shard_id": "0", "type": str(step),
        "sign_r": sig[:32].hex(), "sign_s": sig[32:64].hex(), "sign_v": "0",
    }
    if contract_code:
        data["bytes_code"] = contract_code
    if input_hex:
        data["input"] = input_hex
    if prefund > 0:
        data["prefund"] = str(prefund)

    try:
        resp = requests.post(f"{base_url}/transaction", data=data,
                             verify=verify_ssl, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def fetch_nonce(base_url: str, address: str, verify_ssl: bool = False) -> int:
    """Query account nonce. Returns 0 if account doesn't exist."""
    try:
        r = requests.post(f"{base_url}/query_account",
                          data={"address": address},
                          verify=verify_ssl, timeout=5)
        if r.status_code == 200:
            j = r.json()
            return int(j.get("nonce", 0))
    except Exception:
        pass
    return 0


def batch_query(base_url: str, addresses: List[str],
                verify_ssl: bool = False) -> Dict[str, dict]:
    """Batch query accounts. Returns {addr_hex: account_info}."""
    try:
        r = requests.post(f"{base_url}/query_accounts",
                          data={"addresses": ",".join(addresses)},
                          verify=verify_ssl, timeout=30)
        if r.status_code == 200:
            j = r.json()
            if j.get("status") == 0 and "accounts" in j:
                return j["accounts"]
    except Exception:
        pass
    return {}


# ── Main Test ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    funder_key = sys.argv[3]
    account_count = int(sys.argv[4]) if len(sys.argv) > 4 else 1000
    num_threads = int(sys.argv[5]) if len(sys.argv) > 5 else 8
    rounds = int(sys.argv[6]) if len(sys.argv) > 6 else 5000
    target_tps = int(sys.argv[7]) if len(sys.argv) > 7 else 0

    base_url = f"https://{ip}:{port}"
    funder_addr = get_address(funder_key)

    print(f"\n{'='*70}")
    print(f"  Transfer Stress Test")
    print(f"  Accounts: {account_count}, Threads: {num_threads}")
    print(f"  Rounds: {rounds}, Target TPS: {target_tps or 'unlimited'}")
    print(f"  Node: {ip}:{port}")
    print(f"  Funder: {funder_addr}")
    print(f"{'='*70}")

    # ── Phase 1: Generate accounts ───────────────────────────────────────
    print(f"\n[Phase 1] Generating {account_count} accounts...")
    accounts = []  # list of (prikey_hex, addr_hex)
    for i in range(account_count):
        accounts.append(make_keypair())
        if (i + 1) % 1000 == 0:
            print(f"  Generated {i+1}/{account_count}")
    print(f"  ✓ Generated {account_count} accounts")

    # ── Phase 2: Fund accounts ───────────────────────────────────────────
    print(f"\n[Phase 2] Funding {account_count} accounts...")
    fund_amount = 1_000_000_000
    nonce = fetch_nonce(base_url, funder_addr)
    fund_ok, fund_fail = 0, 0

    for i, (_, addr) in enumerate(accounts):
        nonce += 1
        ok = sign_and_send(base_url, funder_key, addr, fund_amount, nonce)
        if ok:
            fund_ok += 1
        else:
            fund_fail += 1
        if (i + 1) % 500 == 0:
            print(f"  Funded {i+1}/{account_count} (ok={fund_ok}, fail={fund_fail})")
        time.sleep(0.001)  # 1ms throttle

    print(f"  ✓ Funding done: {fund_ok} ok, {fund_fail} fail")

    # ── Phase 3: Verify accounts on chain ────────────────────────────────
    print(f"\n[Phase 3] Waiting 10s for consensus...")
    time.sleep(10)

    print(f"  Batch verifying {account_count} accounts (up to 240s)...")
    pending = list(range(account_count))
    confirmed = 0
    nonces = [0] * account_count
    start = time.time()
    batch_size = 300

    for rnd in range(60):
        if not pending or time.time() - start > 240:
            break
        next_pending = []
        for off in range(0, len(pending), batch_size):
            batch_idx = pending[off:off + batch_size]
            batch_addrs = [accounts[i][1] for i in batch_idx]
            result = batch_query(base_url, batch_addrs)
            for j, idx in enumerate(batch_idx):
                if batch_addrs[j] in result:
                    acc = result[batch_addrs[j]]
                    nonces[idx] = int(acc.get("nonce", "0"))
                    confirmed += 1
                else:
                    next_pending.append(idx)
        pending = next_pending
        elapsed = int(time.time() - start)
        print(f"  [Round {rnd+1}, {elapsed}s] confirmed: {confirmed}/{account_count}, pending: {len(pending)}")
        if not pending:
            break
        time.sleep(3 if confirmed > 0 else 8)

    print(f"  ✓ Verified: {confirmed}/{account_count}")
    if confirmed < account_count * 0.9:
        print("  ✗ Too many accounts unconfirmed. Aborting.")
        sys.exit(1)

    # Build confirmed account list
    confirmed_indices = [i for i in range(account_count) if i not in set(pending)]

    # ── Phase 4: Transfer stress test ────────────────────────────────────
    print(f"\n[Phase 4] Running transfer stress test...")
    print(f"  {len(confirmed_indices)} accounts, {rounds} rounds, {num_threads} threads")

    tx_ok = 0
    tx_fail = 0
    lock = threading.Lock()
    stop_flag = threading.Event()
    stress_start = time.time()

    # Per-thread interval for TPS control
    interval = 0.005  # default 5ms
    if target_tps > 0:
        interval = num_threads / target_tps

    def stress_worker(thread_id: int, total_rounds: int):
        nonlocal tx_ok, tx_fail
        local_ok, local_fail = 0, 0
        n = len(confirmed_indices)
        if n < 2:
            return

        for r in range(total_rounds):
            if stop_flag.is_set():
                break
            # Pick random sender and recipient
            si = random.randint(0, n - 1)
            ri = random.randint(0, n - 2)
            if ri >= si:
                ri += 1
            sender_idx = confirmed_indices[si]
            recip_idx = confirmed_indices[ri]
            pk, _ = accounts[sender_idx]
            _, to_addr = accounts[recip_idx]

            with lock:
                nonces[sender_idx] += 1
                use_nonce = nonces[sender_idx]

            amount = 1 + random.randint(0, 9)
            ok = sign_and_send(base_url, pk, to_addr, amount, use_nonce)
            if ok:
                local_ok += 1
            else:
                local_fail += 1

            time.sleep(interval)

        with lock:
            tx_ok += local_ok
            tx_fail += local_fail

    rounds_per_thread = rounds // num_threads
    threads = []
    for t in range(num_threads):
        r = rounds_per_thread + (1 if t < rounds % num_threads else 0)
        th = threading.Thread(target=stress_worker, args=(t, r))
        threads.append(th)
        th.start()

    # Progress monitor
    while any(th.is_alive() for th in threads):
        time.sleep(2)
        elapsed = time.time() - stress_start
        with lock:
            total = tx_ok + tx_fail
        if elapsed > 0:
            tps = total / elapsed
            print(f"  [{int(elapsed)}s] sent: {total}/{rounds} (ok={tx_ok}, fail={tx_fail}) TPS={tps:.0f}")

    for th in threads:
        th.join()

    elapsed = time.time() - stress_start
    with lock:
        total = tx_ok + tx_fail
    tps = total / elapsed if elapsed > 0 else 0

    # ── Results ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  Transfer Stress Test Results")
    print(f"{'='*70}")
    print(f"  Accounts:  {confirmed}/{account_count}")
    print(f"  Rounds:    {total}/{rounds}")
    print(f"  OK:        {tx_ok}")
    print(f"  Failed:    {tx_fail}")
    print(f"  Duration:  {elapsed:.1f}s")
    print(f"  TPS:       {tps:.0f}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
