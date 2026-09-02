#!/usr/bin/env python3
import sys, os, secrets
sys.path.insert(0, os.path.dirname(__file__))
from test_exchange_contract import (
    HOST, _W3_CACHE, FUNDER_KEY, EXCHANGE_SOL_PATH, DEPLOY_PREFUND,
    setup_all_shards, fund_all_shards, NonceManager, calc_create2_address,
    send_ecdsa_tx, batch_wait_receipts, calc_shard_id, normalize_hex,
)
from seth_sdk import compile_and_link, StepType
import test_exchange_contract as tec

tec.HOST = "192.168.25.129"
tec.FUNDER_KEY = "f1757118b56a13dbb96c41be76b6368b95f78ad07c5d2b04a2e7e1972cd33ae5"
tec.ACCOUNTS_PER_SHARD = 5
tec.CONTRACTS_PER_SHARD = 1

with open(EXCHANGE_SOL_PATH, encoding="utf-8") as f:
    src = f.read()
bc, abi = compile_and_link(src, "Exchange")
bcn = normalize_hex(bc)

bundles = setup_all_shards([3, 4, 5, 6], bc, abi)
fund_all_shards(bundles)
jobs = [j for b in bundles for j in b.jobs]
nm = NonceManager()

for addr in {j.deployer_addr for j in jobs}:
    nm.refresh(addr)

pending = {}
for job in jobs:
    addr = calc_create2_address(job.deployer_addr, job.salt, bcn)
    job.exchange.address = addr
    nonce = nm.next(job.deployer_addr)
    txh, client, ok = send_ecdsa_tx(
        job.deployer_key, addr, int(StepType.kCreateContract), nonce,
        contract_code=bcn, prefund=DEPLOY_PREFUND,
    )
    print(f"{job.tag} deployer={job.deployer_addr[:12]} home={calc_shard_id(job.deployer_addr)} "
          f"nonce={nonce} ok_send={ok} tx={txh[:16]} contract={addr[:16]}")
    if ok:
        pending[job.tag] = (txh, client)

recs = batch_wait_receipts(pending, timeout=120)
for tag, rec in recs.items():
    print(f"  {tag}: status={rec.get('status')} msg={rec.get('msg','')[:80]}")
