#!/usr/bin/env python3
"""
Account transaction history API test.

Usage:
  python3 test_account_tx_history.py <ip> <port> <funder_key> [recipient_key]

Example:
  python3 test_account_tx_history.py 127.0.0.1 23001 7c5b4ec6...66
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3
from Crypto.Hash import keccak
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string_canonize

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256).update(data).digest()


def normalize_hex(value: str) -> str:
    return value[2:] if value.startswith(("0x", "0X")) else value


def get_address(pk_hex: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(normalize_hex(pk_hex)), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    return keccak256(pub)[-20:].hex()


def make_keypair() -> Tuple[str, str]:
    pk_hex = secrets.token_hex(32)
    return pk_hex, get_address(pk_hex)


def fetch_nonce(base_url: str, address: str) -> int:
    try:
        resp = requests.post(
            f"{base_url}/query_account",
            data={"address": normalize_hex(address)},
            verify=False,
            timeout=5,
        )
        if resp.status_code != 200:
            return 0
        return int(resp.json().get("nonce", 0))
    except Exception:
        return 0


def send_transfer(
    base_url: str,
    pk_hex: str,
    to_addr: str,
    amount: int,
    nonce: int,
) -> str:
    sk = SigningKey.from_string(bytes.fromhex(normalize_hex(pk_hex)), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed").hex()
    to_addr = normalize_hex(to_addr)

    msg = bytearray()
    msg.extend(struct.pack("<Q", nonce))
    msg.extend(bytes.fromhex(pub))
    msg.extend(bytes.fromhex(to_addr))
    msg.extend(struct.pack("<Q", amount))
    msg.extend(struct.pack("<Q", 5_000_000))
    msg.extend(struct.pack("<Q", 1))
    msg.extend(struct.pack("<Q", 0))

    tx_hash = keccak256(bytes(msg))
    sig = sk.sign_digest_deterministic(
        tx_hash,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_string_canonize,
    )

    data = {
        "nonce": str(nonce),
        "pubkey": pub,
        "to": to_addr,
        "amount": str(amount),
        "gas_limit": "5000000",
        "gas_price": "1",
        "shard_id": "0",
        "type": "0",
        "sign_r": sig[:32].hex(),
        "sign_s": sig[32:64].hex(),
        "sign_v": "0",
    }
    resp = requests.post(f"{base_url}/transaction", data=data, verify=False, timeout=10)
    print(f"[send_transfer] http={resp.status_code} body={resp.text[:200]}")
    resp.raise_for_status()
    return tx_hash.hex()


def query_account_txs(
    base_url: str,
    address: str,
    limit: int = 20,
    offset: int = 0,
) -> Dict[str, Any]:
    resp = requests.post(
        f"{base_url}/query_account_txs",
        data={
            "address": normalize_hex(address),
            "limit": str(limit),
            "offset": str(offset),
        },
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def tx_matches(tx: Dict[str, Any], sender: str, recipient: str, amount: int) -> bool:
    sender = normalize_hex(sender).lower()
    recipient = normalize_hex(recipient).lower()
    tx_from = str(tx.get("from", "")).lower()
    tx_to = str(tx.get("to", "")).lower()
    tx_amount = int(tx.get("amount", "0") or 0)
    tx_balance = int(tx.get("balance", "0") or 0)

    if tx_from == sender and tx_to == recipient and tx_amount == amount:
        return True

    # Receiver-side local_to records may only carry to/balance.
    if tx_to == recipient and tx_balance >= amount:
        return True

    return False


def wait_history_contains(
    base_url: str,
    address: str,
    sender: str,
    recipient: str,
    amount: int,
    timeout: int = 90,
) -> Optional[List[Dict[str, Any]]]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = query_account_txs(base_url, address)
            txs = result.get("transactions", [])
            if any(tx_matches(tx, sender, recipient, amount) for tx in txs):
                return txs
            print(f"[wait_history] {address[:10]}... count={len(txs)}; retrying")
        except Exception as exc:
            print(f"[wait_history] query failed: {exc}")
        time.sleep(2)
    return None


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 1

    host = sys.argv[1]
    port = int(sys.argv[2])
    funder_key = normalize_hex(sys.argv[3])
    if len(sys.argv) >= 5:
        recipient_key = normalize_hex(sys.argv[4])
        recipient_addr = get_address(recipient_key)
    else:
        recipient_key, recipient_addr = make_keypair()

    base_url = f"https://{host}:{port}"
    funder_addr = get_address(funder_key)
    amount = 1_234_567
    nonce = fetch_nonce(base_url, funder_addr) + 1

    print("=" * 72)
    print("Account transaction history API test")
    print(f"Node:      {base_url}")
    print(f"Sender:    {funder_addr}")
    print(f"Recipient: {recipient_addr}")
    print(f"Amount:    {amount}")
    print(f"Nonce:     {nonce}")
    print("=" * 72)

    tx_hash = send_transfer(base_url, funder_key, recipient_addr, amount, nonce)
    print(f"Sent tx hash: {tx_hash}")

    sender_txs = wait_history_contains(
        base_url, funder_addr, funder_addr, recipient_addr, amount
    )
    if not sender_txs:
        print("FAIL: sender history did not contain the transfer")
        return 2

    recipient_txs = wait_history_contains(
        base_url, recipient_addr, funder_addr, recipient_addr, amount
    )
    if not recipient_txs:
        print("FAIL: recipient history did not contain the transfer")
        return 3

    print("\nSender latest transactions:")
    for tx in sender_txs[:3]:
        print(tx)

    print("\nRecipient latest transactions:")
    for tx in recipient_txs[:3]:
        print(tx)

    print("\nPASS: /query_account_txs returned the transfer for both accounts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
