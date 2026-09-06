#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exchange Contract Multi-Shard Test (parallel batch mode)
========================================================
- All shards run together: batch submit txs, then batch verify
- Account home shard = Hash64(addr) % N + 3
- Funding from shard-3 funder; account queries on home-shard HTTP nodes
"""

from __future__ import annotations
import os, sys, time, secrets, argparse, struct, hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Callable

import requests
import xxhash
from Crypto.Hash import keccak
from ecdsa.util import sigencode_string_canonize
from ecdsa import SigningKey, SECP256k1

sys.path.insert(0, os.path.dirname(__file__))
from shardora_sdk import (
    ShardoraWeb3Mock, ShardoraClient, ShardoraMethod, StepType,
    compile_and_link, calc_create2_address, normalize_hex,
)

# ── Shardora shard constants ──────────────────────────────────────────────────────
HASH_SEED_1 = 23456785675590
UNICAST_ADDR_LEN = 20
CONSENSUS_SHARD_BEGIN = 3
MAX_SHARD_ID = 6

def _hash64(data: bytes) -> int:
    return xxhash.xxh64(data, seed=HASH_SEED_1).intdigest()

def calc_shard_id(addr_hex: str) -> int:
    b = bytes.fromhex(addr_hex.replace("0x", ""))[:UNICAST_ADDR_LEN]
    shard_range = MAX_SHARD_ID - CONSENSUS_SHARD_BEGIN + 1
    return (_hash64(b) % shard_range) + CONSENSUS_SHARD_BEGIN

_W3_CACHE: Dict[int, ShardoraWeb3Mock] = {}

def w3_for_shard(shard: int) -> ShardoraWeb3Mock:
    if shard not in _W3_CACHE:
        _W3_CACHE[shard] = ShardoraWeb3Mock(HOST, SHARD_PORT[shard])
    return _W3_CACHE[shard]

def w3_funder() -> ShardoraWeb3Mock:
    return w3_for_shard(3)

def get_address(pk: str) -> str:
    return w3_funder().client.get_address(pk)

def gen_key_for_shard(target_shard: int) -> Tuple[str, str]:
    while True:
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.verifying_key.to_string("uncompressed")[1:]
        addr = keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()
        if calc_shard_id(addr) == target_shard:
            return sk.to_string().hex(), addr

# ── Config ────────────────────────────────────────────────────────────────────
HOST = os.environ.get("SHARDORA_HOST", "127.0.0.1")
SHARDS = [3, 4, 5, 6]
SHARD_PORT = {s: int(f"2{s}001") for s in SHARDS}

CONTRACTS_PER_SHARD = 10
ACCOUNTS_PER_SHARD = 100
INITIAL_BALANCE = 50_000_000
DEPLOYER_BALANCE = 500_000_000
CONTRACT_PREFUND = 5_000_000
ITEM_PRICE = 100_000
PURCHASE_VALUE = 150_000

FUND_SETTLE_SEC = 15
FUND_VERIFY_TIMEOUT = 180
TX_SETTLE_SEC = 8
BATCH_TX_TIMEOUT = 120
POLL_INTERVAL = 1

FUNDER_KEY = "551056079365157182d65d8f5a637edb6a6140c349373a01f1423b918e18c40b"
EXCHANGE_SOL_PATH = os.path.join(
    os.path.dirname(__file__), "../src/contract/tests/contracts/exchange.sol"
)
DEPLOY_PREFUND = 10_000_000
CALL_PREFUND = 1_000_000


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ContractJob:
    shard: int
    index: int
    deployer_key: str
    deployer_addr: str
    seller_key: str
    seller_addr: str
    buyer_key1: str
    buyer_addr1: str
    buyer_key2: str
    salt: str = ""
    exchange: object = None
    item_hash: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    item_hash2: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    item_info: bytes = b""
    start_ms: int = 0
    end_ms: int = 0
    passed: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)

    @property
    def tag(self) -> str:
        return f"s{self.shard}c{self.index}"


@dataclass
class ShardBundle:
    shard: int
    keys: List[str]
    addrs: List[str]
    deployer_key: str
    deployer_addr: str
    seller_keys: List[str]
    seller_addrs: List[str]
    buyer_keys: List[str]
    buyer_addrs: List[str]
    jobs: List[ContractJob] = field(default_factory=list)


# ── Account query (home shard) ────────────────────────────────────────────────

def query_account_on_shard(shard: int, addr: str) -> Optional[dict]:
    client = w3_for_shard(shard).client
    try:
        r = requests.post(
            client.query_url, data={"address": addr},
            timeout=5, verify=client.verify_ssl,
        )
        text = r.text or ""
        if "get address failed" in text or r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

def query_account_home(addr: str) -> Optional[dict]:
    return query_account_on_shard(calc_shard_id(addr), addr)

def batch_query_on_shard(shard: int, addrs: List[str]) -> Dict[str, dict]:
    if not addrs:
        return {}
    client = w3_for_shard(shard).client
    try:
        r = requests.post(
            f"{client.base_url}/query_accounts",
            data={"addresses": ",".join(addrs)},
            timeout=60, verify=client.verify_ssl,
        )
        if r.status_code == 200:
            j = r.json()
            if j.get("status") == 0 and "accounts" in j:
                return j["accounts"]
    except Exception:
        pass
    return {}

def norm_addr(a: str) -> str:
    return a.lower().replace("0x", "")


def wait_accounts_on_home_shards(addrs: List[str], amount: int, timeout: int) -> int:
    pending = {norm_addr(a) for a in addrs}
    deadline = time.time() + timeout
    while pending and time.time() < deadline:
        by_shard: Dict[int, List[str]] = {}
        for a in addrs:
            na = norm_addr(a)
            if na not in pending:
                continue
            by_shard.setdefault(calc_shard_id(a), []).append(a)
        for shard, shard_addrs in by_shard.items():
            found = batch_query_on_shard(shard, shard_addrs)
            for key, info in found.items():
                if norm_addr(key) in pending and int(info.get("balance", 0)) >= amount:
                    pending.discard(norm_addr(key))
            for a in shard_addrs:
                na = norm_addr(a)
                if na not in pending:
                    continue
                info = query_account_on_shard(shard, a)
                if info and int(info.get("balance", 0)) >= amount:
                    pending.discard(na)
        time.sleep(POLL_INTERVAL)
    return len(addrs) - len(pending)


# ── Nonce + tx send ───────────────────────────────────────────────────────────

class NonceManager:
    """Track tx nonces; contract execute/refund use composite address (contract+sender)."""

    def __init__(self) -> None:
        self._nonce: Dict[str, int] = {}

    @staticmethod
    def _norm(addr: str) -> str:
        return addr.lower().replace("0x", "")

    @staticmethod
    def key(addr: str, to: str = "", step: int = 0) -> str:
        a = NonceManager._norm(addr)
        if step in (int(StepType.kContractExcute), int(StepType.kContractRefund)):
            return f"x:{NonceManager._norm(to)}{a}"
        return a

    def _query_addr(self, addr: str, to: str, step: int) -> str:
        if step in (int(StepType.kContractExcute), int(StepType.kContractRefund)):
            return self._norm(to) + self._norm(addr)
        return self._norm(addr)

    def _load(self, addr: str, to: str = "", step: int = 0) -> int:
        query_addr = self._query_addr(addr, to, step)
        info = query_account_on_shard(calc_shard_id(addr), query_addr)
        return int(info.get("nonce", 0)) if info else 0

    def next(self, addr: str, to: str = "", step: int = 0) -> int:
        k = self.key(addr, to, step)
        if k not in self._nonce:
            self._nonce[k] = self._load(addr, to, step)
        self._nonce[k] += 1
        return self._nonce[k]

    def refresh(self, addr: str, to: str = "", step: int = 0) -> None:
        k = self.key(addr, to, step)
        self._nonce[k] = self._load(addr, to, step)

    def refresh_many(self, specs: List[Tuple[str, str, int]]) -> None:
        for addr, to, step in specs:
            self.refresh(addr, to, step)


def client_for_sender(pk: str) -> ShardoraClient:
    return w3_for_shard(calc_shard_id(get_address(pk))).client


def send_with_nonce(
    client: ShardoraClient,
    pk_hex: str,
    to: str,
    step: int,
    nonce: int,
    *,
    amount: int = 0,
    contract_code: str = "",
    input_hex: str = "",
    prefund: int = 0,
) -> Tuple[str, bool]:
    """Build and POST a signed tx (SDK-compatible)."""
    contract_code = normalize_hex(contract_code)
    input_hex = normalize_hex(input_hex)
    sk = SigningKey.from_string(bytes.fromhex(pk_hex.replace("0x", "")), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed").hex()
    msg = bytearray()
    msg.extend(struct.pack("<Q", nonce))
    msg.extend(bytes.fromhex(pub))
    msg.extend(bytes.fromhex(to.replace("0x", "")))
    msg.extend(struct.pack("<Q", amount))
    msg.extend(struct.pack("<Q", 5_000_000))
    msg.extend(struct.pack("<Q", 1))
    msg.extend(struct.pack("<Q", int(step)))
    if contract_code:
        msg.extend(bytes.fromhex(contract_code))
    if input_hex:
        msg.extend(bytes.fromhex(input_hex))
    if prefund > 0:
        msg.extend(struct.pack("<Q", prefund))
    txh = keccak.new(digest_bits=256).update(msg).digest()
    sig = sk.sign_digest_deterministic(
        txh, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize
    )
    data = {
        "nonce": str(nonce),
        "pubkey": pub,
        "to": to,
        "amount": str(amount),
        "gas_limit": "5000000",
        "gas_price": "1",
        "shard_id": "0",
        "type": str(int(step)),
        "sign_r": sig[:32].hex(),
        "sign_s": sig[32:64].hex(),
        "sign_v": "0",
    }
    if contract_code:
        data["bytes_code"] = contract_code
    if input_hex:
        data["input"] = input_hex
    if prefund:
        data["prefund"] = str(prefund)
    try:
        resp = requests.post(client.tx_url, data=data, timeout=10, verify=client.verify_ssl)
        body = resp.text or ""
        if resp.status_code == 200 and "kTxUserNonceInvalid" in body:
            my_addr = client.get_address(pk_hex)
            if step in (int(StepType.kContractExcute), int(StepType.kContractRefund)):
                query_addr = to.replace("0x", "").lower() + my_addr.lower()
            else:
                query_addr = my_addr
            try:
                r2 = requests.post(
                    client.query_url, data={"address": query_addr},
                    timeout=5, verify=client.verify_ssl,
                ).json()
                nonce = int(r2.get("nonce", 0)) + 1
                data["nonce"] = str(nonce)
                msg = bytearray()
                msg.extend(struct.pack("<Q", nonce))
                msg.extend(bytes.fromhex(pub))
                msg.extend(bytes.fromhex(to.replace("0x", "")))
                msg.extend(struct.pack("<Q", amount))
                msg.extend(struct.pack("<Q", 5_000_000))
                msg.extend(struct.pack("<Q", 1))
                msg.extend(struct.pack("<Q", int(step)))
                if contract_code:
                    msg.extend(bytes.fromhex(contract_code))
                if input_hex:
                    msg.extend(bytes.fromhex(input_hex))
                if prefund > 0:
                    msg.extend(struct.pack("<Q", prefund))
                txh = keccak.new(digest_bits=256).update(msg).digest()
                sig = sk.sign_digest_deterministic(
                    txh, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize
                )
                data["sign_r"] = sig[:32].hex()
                data["sign_s"] = sig[32:64].hex()
                resp = requests.post(client.tx_url, data=data, timeout=10, verify=client.verify_ssl)
                body = resp.text or ""
            except Exception:
                pass
        ok_send = resp.status_code == 200 and "kTxUserNonceInvalid" not in body
        return txh.hex(), ok_send
    except Exception:
        return txh.hex(), False


def send_ecdsa_tx(
    sender_pk: str,
    to: str,
    step: int,
    nonce: int,
    *,
    amount: int = 0,
    contract_code: str = "",
    input_hex: str = "",
    prefund: int = 0,
) -> Tuple[str, ShardoraClient, bool]:
    client = client_for_sender(sender_pk)
    txh, ok_send = send_with_nonce(
        client, sender_pk, to, step, nonce,
        amount=amount, contract_code=contract_code,
        input_hex=input_hex, prefund=prefund,
    )
    return txh, client, ok_send


def _poll_receipt(client: ShardoraClient, tx_hash: str) -> Optional[dict]:
    try:
        r = requests.post(
            client.receipt_url, data={"tx_hash": tx_hash},
            timeout=5, verify=client.verify_ssl,
        )
        resp = r.json()
        status = resp.get("status")
        if status in (10001, 10003, 100010):
            return None
        return resp
    except Exception:
        return None


def batch_wait_receipts(
    pending: Dict[str, Tuple[str, ShardoraClient]],
    timeout: int = BATCH_TX_TIMEOUT,
) -> Dict[str, dict]:
    """Wait for all tx receipts. Missing entries get status=-1."""
    results: Dict[str, dict] = {}
    left = dict(pending)
    deadline = time.time() + timeout
    while left and time.time() < deadline:
        done = []
        for label, (txh, client) in left.items():
            rec = _poll_receipt(client, txh)
            if rec is not None:
                results[label] = rec
                done.append(label)
        for label in done:
            del left[label]
        if left:
            time.sleep(POLL_INTERVAL)
    for label, (txh, client) in left.items():
        results[label] = {"status": -1, "msg": "timeout", "tx_hash": txh}
    return results


NONCE_INVALID = 10007
CONTRACT_ADDR_LOCKED = 5023


def sync_execute_nonces(jobs: List[ContractJob], nm: NonceManager) -> None:
    """Refresh composite (contract+sender) nonces after prefund settles."""
    step = int(StepType.kContractExcute)
    seen: set = set()
    for job in jobs:
        if "deploy" not in job.passed:
            continue
        contract = job.exchange.address
        for pk in (job.seller_key, job.buyer_key1, job.buyer_key2):
            addr = get_address(pk)
            k = NonceManager.key(addr, contract, step)
            if k in seen:
                continue
            seen.add(k)
            nm.refresh(addr, contract, step)


def fund_all_accounts(addrs: List[str], target_balance: int) -> None:
    """Fund accounts to reach target_balance (sends delta only)."""
    funder_addr = get_address(FUNDER_KEY)
    finfo = query_account_on_shard(3, funder_addr)
    if finfo is None:
        raise RuntimeError(f"funder {funder_addr[:16]} not found on shard 3")
    funder_bal = int(finfo.get("balance", 0))
    print(f"  funder {funder_addr[:16]}... balance={funder_bal}")

    to_fund: List[Tuple[str, int]] = []
    for a in addrs:
        info = query_account_home(a)
        bal = int(info.get("balance", 0)) if info else 0
        need = target_balance - bal
        if need > 0:
            to_fund.append((a, need))
    if not to_fund:
        return

    fund_pending: Dict[str, Tuple[str, ShardoraClient]] = {}
    fc = w3_funder().client
    nonce = int(finfo.get("nonce", 0))
    for a, need in to_fund:
        nonce += 1
        txh, ok_send = send_with_nonce(
            fc, FUNDER_KEY, a, int(StepType.kNormalFrom), nonce, amount=need
        )
        if ok_send:
            fund_pending[norm_addr(a)] = (txh, fc)
    print(f"  funding: sent {len(to_fund)} txs")
    if fund_pending:
        recs = batch_wait_receipts(fund_pending, timeout=300)
        ok_rec = sum(1 for r in recs.values() if r.get("status") == 0)
        print(f"  funding receipts OK: {ok_rec}/{len(fund_pending)}")
    print(f"  waiting {FUND_SETTLE_SEC}s for cross-shard settlement...")
    time.sleep(FUND_SETTLE_SEC)
    verified = wait_accounts_on_home_shards(
        [a for a, _ in to_fund], target_balance, FUND_VERIFY_TIMEOUT
    )
    if verified < len(to_fund):
        raise RuntimeError(
            f"only {verified}/{len(to_fund)} accounts reached balance>={target_balance}"
        )


# ── Setup all shards ──────────────────────────────────────────────────────────

def setup_all_shards(shards: List[int], bytecode: str, abi: list) -> List[ShardBundle]:
    bundles: List[ShardBundle] = []
    print(f"\n[Phase 1] Generating accounts for shards {shards}...")
    for shard in shards:
        keys, addrs = [], []
        for _ in range(ACCOUNTS_PER_SHARD):
            k, a = gen_key_for_shard(shard)
            keys.append(k)
            addrs.append(a)
        n_sellers = max(2, ACCOUNTS_PER_SHARD // 3)
        b = ShardBundle(
            shard=shard,
            keys=keys,
            addrs=addrs,
            deployer_key=keys[0],
            deployer_addr=addrs[0],
            seller_keys=keys[1:1 + n_sellers],
            seller_addrs=addrs[1:1 + n_sellers],
            buyer_keys=keys[1 + n_sellers:],
            buyer_addrs=addrs[1 + n_sellers:],
        )
        w3 = w3_for_shard(shard)
        for ci in range(CONTRACTS_PER_SHARD):
            b.jobs.append(ContractJob(
                shard=shard,
                index=ci,
                deployer_key=b.deployer_key,
                deployer_addr=b.deployer_addr,
                seller_key=b.seller_keys[ci % len(b.seller_keys)],
                seller_addr=b.seller_addrs[ci % len(b.seller_addrs)],
                buyer_key1=b.buyer_keys[ci % len(b.buyer_keys)],
                buyer_addr1=b.buyer_addrs[ci % len(b.buyer_addrs)],
                buyer_key2=b.buyer_keys[(ci + 1) % len(b.buyer_keys)],
                salt=secrets.token_hex(31) + f"{ci:02x}",
                exchange=w3.shardora.contract(abi=abi, bytecode=bytecode, sender_address=b.deployer_addr),
            ))
        bundles.append(b)
        print(f"  shard {shard}: {ACCOUNTS_PER_SHARD} accounts, {CONTRACTS_PER_SHARD} contracts")
    return bundles


def fund_all_shards(bundles: List[ShardBundle]) -> None:
    print(f"\n[Phase 2] Funding all shards via shard-3 funder...")
    all_addrs: List[str] = []
    deployers: List[str] = []
    for b in bundles:
        all_addrs.extend(b.addrs)
        deployers.append(b.deployer_addr)
    fund_all_accounts(all_addrs, INITIAL_BALANCE)
    fund_all_accounts(deployers, DEPLOYER_BALANCE)
    print(f"  done: {len(all_addrs)} accounts, deployers topped to {DEPLOYER_BALANCE}")


# ── Batch deploy / prefund / call helpers ─────────────────────────────────────

def batch_deploy_all(jobs: List[ContractJob], bytecode: str, nm: NonceManager) -> None:
    print(f"\n[Phase 3] Batch deploy {len(jobs)} contracts...")
    bc = normalize_hex(bytecode)
    deploy_step = int(StepType.kCreateContract)
    todo = list(jobs)
    ok_n = 0

    for round_i in range(3):
        if not todo:
            break
        for deployer in {j.deployer_addr for j in todo}:
            nm.refresh(deployer, step=deploy_step)

        pending: Dict[str, Tuple[str, ShardoraClient]] = {}
        for job in todo:
            job.failed = [f for f in job.failed if not f.startswith("deploy:")]
            addr = calc_create2_address(job.deployer_addr, job.salt, bc)
            job.exchange.address = addr
            nonce = nm.next(job.deployer_addr, step=deploy_step)
            txh, client, ok_send = send_ecdsa_tx(
                job.deployer_key, addr, deploy_step, nonce,
                contract_code=bc, prefund=DEPLOY_PREFUND,
            )
            if ok_send:
                pending[f"{job.tag}_deploy"] = (txh, client)
            else:
                job.failed.append("deploy: send failed")

        if not pending:
            break
        receipts = batch_wait_receipts(pending)
        next_todo: List[ContractJob] = []
        for job in todo:
            rec = receipts.get(f"{job.tag}_deploy")
            if rec is None:
                if not any(f.startswith("deploy:") for f in job.failed):
                    job.failed.append("deploy: no receipt")
                continue
            if rec.get("status") in (0, CONTRACT_ADDR_LOCKED):
                job.passed.append("deploy")
                ok_n += 1
            elif rec.get("status") == NONCE_INVALID and round_i < 2:
                next_todo.append(job)
            else:
                job.failed.append(
                    f"deploy: status={rec.get('status')} msg={rec.get('msg', '')[:60]}"
                )
        todo = next_todo
        if todo:
            time.sleep(2)

    print(f"  deploy OK: {ok_n}/{len(jobs)}")
    for addr in {j.deployer_addr for j in jobs}:
        nm.refresh(addr, step=deploy_step)
    time.sleep(TX_SETTLE_SEC)


def batch_prefund_all(jobs: List[ContractJob], nm: NonceManager) -> None:
    active = [j for j in jobs if "deploy" in j.passed]
    prefund_step = int(StepType.kContractGasPrefund)
    print(f"\n[Phase 4] Batch prefund {len(active) * 4} entries...")

    entries: List[Tuple[ContractJob, str, str]] = []
    for job in active:
        for role, pk in [
            ("d", job.deployer_key),
            ("s", job.seller_key),
            ("b1", job.buyer_key1),
            ("b2", job.buyer_key2),
        ]:
            entries.append((job, role, pk))

    todo = entries
    ok_n = 0
    for round_i in range(3):
        if not todo:
            break
        for _, _, pk in todo:
            nm.refresh(get_address(pk), step=prefund_step)

        pending: Dict[str, Tuple[str, ShardoraClient]] = {}
        for job, role, pk in todo:
            addr = get_address(pk)
            nonce = nm.next(addr, step=prefund_step)
            txh, client, ok_send = send_ecdsa_tx(
                pk, job.exchange.address, prefund_step,
                nonce, prefund=CONTRACT_PREFUND,
            )
            if ok_send:
                pending[f"{job.tag}_pf_{role}"] = (txh, client)

        if not pending:
            break
        receipts = batch_wait_receipts(pending)
        next_todo: List[Tuple[ContractJob, str, str]] = []
        for job, role, pk in todo:
            label = f"{job.tag}_pf_{role}"
            rec = receipts.get(label)
            if rec and rec.get("status") == 0:
                ok_n += 1
            elif rec and rec.get("status") == NONCE_INVALID and round_i < 2:
                next_todo.append((job, role, pk))
        todo = next_todo
        if todo:
            time.sleep(2)

    print(f"  prefund OK: {ok_n}/{len(entries)}")
    time.sleep(TX_SETTLE_SEC)


def _encode_call(job: ContractJob, fn: str, *args) -> str:
    method: ShardoraMethod = getattr(job.exchange.functions, fn)(*args)
    return method.encoded_input


def batch_contract_calls(
    jobs: List[ContractJob],
    phase: str,
    nm: NonceManager,
    build: Callable[[ContractJob], Tuple[str, str, int, int]],
    *,
    expect_revert: bool = False,
) -> None:
    exec_step = int(StepType.kContractExcute)
    specs: List[Tuple[ContractJob, str, str, int, int]] = []
    for job in jobs:
        if not job.exchange or not job.exchange.address:
            continue
        if "deploy" not in job.passed:
            continue
        try:
            pk, input_hex, value, prefund = build(job)
        except Exception as e:
            job.failed.append(f"{phase}: encode {e}")
            continue
        specs.append((job, pk, input_hex, value, prefund))

    if not specs:
        return

    todo = specs
    ok_n = 0
    for round_i in range(3):
        if not todo:
            break
        seen: set = set()
        for job, pk, _, _, _ in todo:
            addr = get_address(pk)
            k = NonceManager.key(addr, job.exchange.address, exec_step)
            if k not in seen:
                seen.add(k)
                nm.refresh(addr, job.exchange.address, exec_step)

        pending: Dict[str, Tuple[str, ShardoraClient]] = {}
        meta: Dict[str, ContractJob] = {}
        for job, pk, input_hex, value, prefund in todo:
            job.failed = [f for f in job.failed if not f.startswith(f"{phase}:")]
            addr = get_address(pk)
            nonce = nm.next(addr, job.exchange.address, exec_step)
            txh, client, ok_send = send_ecdsa_tx(
                pk, job.exchange.address, exec_step,
                nonce, amount=value, input_hex=input_hex, prefund=prefund,
            )
            if ok_send:
                label = f"{job.tag}_{phase}"
                pending[label] = (txh, client)
                meta[label] = job

        if not pending:
            break
        receipts = batch_wait_receipts(pending)
        next_todo: List[Tuple[ContractJob, str, str, int, int]] = []
        for job, pk, input_hex, value, prefund in todo:
            label = f"{job.tag}_{phase}"
            rec = receipts.get(label)
            if rec is None:
                if not any(f.startswith(f"{phase}:") for f in job.failed):
                    job.failed.append(f"{phase}: no receipt")
                continue
            st = rec.get("status")
            if expect_revert:
                if st != 0:
                    job.passed.append(phase)
                    ok_n += 1
                elif st == NONCE_INVALID and round_i < 2:
                    next_todo.append((job, pk, input_hex, value, prefund))
                else:
                    job.failed.append(f"{phase}: expected revert")
            else:
                if st == 0:
                    job.passed.append(phase)
                    ok_n += 1
                elif st == NONCE_INVALID and round_i < 2:
                    next_todo.append((job, pk, input_hex, value, prefund))
                else:
                    job.failed.append(f"{phase}: status={st}")
        todo = next_todo
        if todo:
            time.sleep(2)

    print(f"  {phase}: receipts OK {ok_n}/{len(specs)}")
    time.sleep(TX_SETTLE_SEC)


def run_view_tests(jobs: List[ContractJob]) -> None:
    active = [j for j in jobs if "deploy" in j.passed]
    print(f"\n[Phase views] Query {len(active)} contracts...")
    for job in active:
        ex = job.exchange
        try:
            ret = ex.functions.GetAllItemJson(0, 10).call()
            job.passed.append("GetAllItemJson")
        except Exception as e:
            job.failed.append(f"GetAllItemJson: {e}")
        try:
            ex.functions.GetOwnerItemJson(0, 10, job.seller_addr).call()
            job.passed.append("GetOwnerItemJson")
        except Exception as e:
            job.failed.append(f"GetOwnerItemJson: {e}")
        try:
            ex.functions.GetSellDetail(job.item_hash).call()
            job.passed.append("GetSellDetail")
        except Exception as e:
            job.failed.append(f"GetSellDetail: {e}")
        try:
            ex.functions.item_map(job.item_hash).call()
            job.passed.append("item_map_getter")
        except Exception as e:
            job.failed.append(f"item_map_getter: {e}")
        try:
            ex.functions.id_with_hash_map(0).call()
            job.passed.append("id_with_hash_map")
        except Exception as e:
            job.failed.append(f"id_with_hash_map: {e}")


def run_all_contract_phases(jobs: List[ContractJob], nm: NonceManager) -> None:
    now = int(time.time() * 1000)
    for j in jobs:
        j.start_ms = now
        j.end_ms = now + 86_400_000
        j.item_info = f"shard{j.shard}_c{j.index}_item0".encode()

    print(f"\n[Phase 5] Batch CreateNewItem x{len(jobs)}...")
    batch_contract_calls(jobs, "CreateNewItem", nm, lambda j: (
        j.seller_key,
        _encode_call(j, "CreateNewItem", j.item_hash, j.item_info, ITEM_PRICE, j.start_ms, j.end_ms),
        0, CALL_PREFUND,
    ))
    time.sleep(TX_SETTLE_SEC)

    print(f"[Phase 6] Batch CreateNewItem#2 x{len(jobs)} (best-effort)...")
    batch_contract_calls(jobs, "CreateNewItem2", nm, lambda j: (
        j.seller_key,
        _encode_call(j, "CreateNewItem", j.item_hash2,
                     f"shard{j.shard}_c{j.index}_item1".encode(),
                     ITEM_PRICE, j.start_ms, j.end_ms),
        0, CALL_PREFUND,
    ))
    time.sleep(TX_SETTLE_SEC)

    print(f"[Phase 7] Batch PurchaseItem buyer1 x{len(jobs)}...")
    batch_contract_calls(jobs, "PurchaseItem_buyer1", nm, lambda j: (
        j.buyer_key1,
        _encode_call(j, "PurchaseItem", j.item_hash, int(time.time() * 1000)),
        PURCHASE_VALUE, CALL_PREFUND,
    ))
    time.sleep(TX_SETTLE_SEC)

    print(f"[Phase 8] Batch PurchaseItem buyer2 x{len(jobs)}...")
    batch_contract_calls(jobs, "PurchaseItem_buyer2", nm, lambda j: (
        j.buyer_key2,
        _encode_call(j, "PurchaseItem", j.item_hash, int(time.time() * 1000)),
        PURCHASE_VALUE + 50_000, CALL_PREFUND,
    ))
    time.sleep(TX_SETTLE_SEC)

    print(f"[Phase 9] Batch ConfirmPurchase x{len(jobs)}...")
    batch_contract_calls(jobs, "ConfirmPurchase", nm, lambda j: (
        j.seller_key,
        _encode_call(j, "ConfirmPurchase", j.item_hash),
        0, CALL_PREFUND,
    ))
    time.sleep(TX_SETTLE_SEC)

    run_view_tests(jobs)

    print(f"[Phase 10] Batch duplicate CreateNewItem (expect revert) x{len(jobs)}...")
    batch_contract_calls(jobs, "duplicate_revert", nm, lambda j: (
        j.seller_key,
        _encode_call(j, "CreateNewItem", j.item_hash, j.item_info, ITEM_PRICE, j.start_ms, j.end_ms),
        0, CALL_PREFUND,
    ), expect_revert=True)

    print(f"[Phase 11] Batch owner PurchaseItem (expect revert) x{len(jobs)}...")
    batch_contract_calls(jobs, "owner_purchase_revert", nm, lambda j: (
        j.seller_key,
        _encode_call(j, "PurchaseItem", j.item_hash2, int(time.time() * 1000)),
        PURCHASE_VALUE, CALL_PREFUND,
    ), expect_revert=True)


def run_parallel(shards: List[int], bytecode: str, abi: list) -> List[dict]:
    bundles = setup_all_shards(shards, bytecode, abi)
    fund_all_shards(bundles)
    all_jobs = [j for b in bundles for j in b.jobs]
    nm = NonceManager()

    batch_deploy_all(all_jobs, bytecode, nm)
    batch_prefund_all(all_jobs, nm)
    sync_execute_nonces(all_jobs, nm)
    run_all_contract_phases(all_jobs, nm)

    results = []
    for b in bundles:
        cr_list = []
        for job in b.jobs:
            cr_list.append({
                "index": job.index,
                "address": job.exchange.address if job.exchange else None,
                "passed": job.passed,
                "failed": job.failed,
            })
        results.append({"shard": b.shard, "contracts": cr_list, "errors": []})
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global HOST, CONTRACTS_PER_SHARD, ACCOUNTS_PER_SHARD, FUNDER_KEY, _W3_CACHE
    parser = argparse.ArgumentParser(description="Exchange contract multi-shard test")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--shards", default=",".join(map(str, SHARDS)))
    parser.add_argument("--contracts", type=int, default=CONTRACTS_PER_SHARD)
    parser.add_argument("--accounts", type=int, default=ACCOUNTS_PER_SHARD)
    parser.add_argument("--funder-key", default=FUNDER_KEY)
    args = parser.parse_args()

    HOST = args.host
    CONTRACTS_PER_SHARD = args.contracts
    ACCOUNTS_PER_SHARD = args.accounts
    FUNDER_KEY = args.funder_key
    _W3_CACHE.clear()
    shards = [int(s) for s in args.shards.split(",")]

    print("Exchange Contract Multi-Shard Test (parallel batch)")
    print(f"  Shards     : {shards}")
    print(f"  Contracts  : {CONTRACTS_PER_SHARD} per shard")
    print(f"  Accounts   : {ACCOUNTS_PER_SHARD} per shard")
    print(f"  Host       : {HOST}")

    print("\nCompiling Exchange contract...")
    with open(EXCHANGE_SOL_PATH, encoding="utf-8") as f:
        source = f.read()
    bytecode, abi = compile_and_link(source, "Exchange")
    print(f"  bytecode {len(bytecode)} chars, "
          f"{len([x for x in abi if x['type'] == 'function'])} functions")

    start = time.time()
    all_results = run_parallel(shards, bytecode, abi)

    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    total_p = total_f = total_c = 0
    for sr in all_results:
        s = sr["shard"]
        for cr in sr["contracts"]:
            total_c += 1
            p, f = len(cr["passed"]), len(cr["failed"])
            total_p += p
            total_f += f
            tag = "OK" if f == 0 else "FAIL"
            print(f"  Shard {s} Contract {cr['index']+1:2d}  {cr['address'] or 'N/A':42s}  "
                  f"passed={p:2d} failed={f:2d}  [{tag}]")
            for msg in cr["failed"]:
                print(f"      FAIL: {msg}")
        for e in sr.get("errors", []):
            print(f"  Shard {s} ERROR: {e}")
    print("-" * 60)
    print(f"  Total contracts : {total_c}")
    print(f"  Total passed    : {total_p}")
    print(f"  Total failed    : {total_f}")
    print(f"  Duration        : {time.time() - start:.1f}s")
    print("=" * 60)
    return 0 if total_f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
