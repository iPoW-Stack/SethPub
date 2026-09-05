#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deploy Exchange contract + 100 test accounts with prefund.
Runs inside seth-builder container via deploy_exchange.sh.

Output: /data/tmp/exchange_deploy_result.json
  - contract_address
  - accounts[]: {index, private_key, address}
"""
import time, sys, os, secrets, json
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from seth_sdk import (
    SethClient, SethWeb3Mock, StepType, compile_and_link, normalize_hex,
    calc_create2_address,
)

import xxhash
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak

from solcx import install_solc
install_solc("0.8.34")

HOST = os.environ.get("SETH_HOST", "127.0.0.1")
PORT = int(os.environ.get("SETH_PORT", "23001"))
FUNDER_KEY = os.environ["FUNDER_KEY"]
NUM_ACCOUNTS = int(os.environ.get("NUM_ACCOUNTS", "100"))
FUND_AMOUNT = int(os.environ.get("FUND_AMOUNT", "500000000"))
PREFUND_AMOUNT = int(os.environ.get("PREFUND_AMOUNT", "100000000"))
CALL_PREFUND = int(os.environ.get("CALL_PREFUND", "10000000"))
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "/data/tmp/exchange_deploy_result.json")
BATCH_WORKERS = int(os.environ.get("BATCH_WORKERS", "20"))

# 账户/合约必须归属发交易的分片，否则节点报 address invalid / kNotExists
TARGET_SHARD = int(os.environ.get("TARGET_SHARD", "3"))
HASH_SEED_1 = 23456785675590
CONSENSUS_SHARD_BEGIN = 3
MAX_SHARD_ID = 6

def calc_shard_id(addr_hex: str) -> int:
    b = bytes.fromhex(addr_hex.replace("0x", ""))[:20]
    shard_range = MAX_SHARD_ID - CONSENSUS_SHARD_BEGIN + 1
    return (xxhash.xxh64(b, seed=HASH_SEED_1).intdigest() % shard_range) + CONSENSUS_SHARD_BEGIN

def gen_key_on_shard(shard: int):
    while True:
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.verifying_key.to_string("uncompressed")[1:]
        addr = keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()
        if calc_shard_id(addr) == shard:
            return sk.to_string().hex(), addr

def find_salt_on_shard(sender: str, bytecode: str, shard: int) -> str:
    for _ in range(65536):
        s = secrets.token_hex(32)
        if calc_shard_id(calc_create2_address(sender, s, bytecode)) == shard:
            return s
    raise RuntimeError(f"no CREATE2 salt found for shard {shard}")

client = SethClient(HOST, PORT)
w3 = SethWeb3Mock(HOST, PORT)

print("=" * 60)
print("  EXCHANGE CONTRACT DEPLOYMENT")
print(f"  Host: {HOST}:{PORT}")
print(f"  Accounts: {NUM_ACCOUNTS}")
print("=" * 60)

# 1. Compile
print("\n[1/6] Compiling Exchange contract...")
sol_path = os.path.join(os.path.dirname(__file__), "src/contract/tests/contracts/exchange.sol")
with open(sol_path) as f:
    source = f.read()
bytecode, abi = compile_and_link(source, "Exchange")
print(f"  Compiled: bytecode={len(bytecode)} chars, abi={len(abi)} items")

# 2. Deploy
print(f"\n[2/6] Deploying Exchange contract...")
funder_addr = client.get_address(FUNDER_KEY)
print(f"  Funder: {funder_addr}")

contract = w3.contract(abi=abi, bytecode=bytecode, sender_address=funder_addr)
salt = find_salt_on_shard(funder_addr, bytecode, TARGET_SHARD)
deployed = contract.deploy({"from": funder_addr, "salt": salt}, FUNDER_KEY)
contract_addr = deployed.address
deploy_status = deployed.deploy_receipt.get("status")
print(f"  Contract: {contract_addr} (shard {calc_shard_id(contract_addr)})")
print(f"  Deploy status: {deploy_status}")

if deploy_status != 0:
    print("FATAL: Deploy failed!")
    sys.exit(1)

# 3. Generate accounts
print(f"\n[3/6] Generating {NUM_ACCOUNTS} test accounts (all on shard {TARGET_SHARD})...")
accounts = []
for i in range(NUM_ACCOUNTS):
    sk, addr = gen_key_on_shard(TARGET_SHARD)
    accounts.append({"index": i, "private_key": sk, "address": addr})
    if (i + 1) % 25 == 0:
        print(f"  Generated {i + 1}/{NUM_ACCOUNTS}")

# 校验所有账户确实在 TARGET_SHARD
wrong = [(i, a["address"], calc_shard_id(a["address"])) for i, a in enumerate(accounts)
         if calc_shard_id(a["address"]) != TARGET_SHARD]
if wrong:
    print(f"FATAL: {len(wrong)} accounts not on shard {TARGET_SHARD}: {wrong}")
    sys.exit(1)
print(f"  Shard check: all {NUM_ACCOUNTS} accounts on shard {TARGET_SHARD} OK")

# 4. Fund all accounts — 串行逐笔发送，每笔等收据后再发下一笔，彻底避免 nonce 碰撞
# 并发 send_transaction_auto 时 SDK 内部 nonce 管理无法跨线程序列化，20 笔并发会
# 拿到同一 nonce，链只处理第一笔，其余全部 kTxUserNonceInvalid(10007)。
print(f"\n[4/6] Funding {NUM_ACCOUNTS} accounts ({FUND_AMOUNT} each, serial)...")
time.sleep(5)

ok_fund = 0
for i, acc in enumerate(accounts):
    for attempt in range(3):
        try:
            txh = client.send_transaction_auto(FUNDER_KEY, acc["address"], StepType.kNormalFrom, amount=FUND_AMOUNT)
            rec = client.wait_for_receipt(txh, timeout=120)
            if rec and rec.get("status") == 0:
                ok_fund += 1
                break
            elif rec and rec.get("status") == 10007 and attempt < 2:
                time.sleep(2)  # nonce 短暂不一致，重试
                continue
            else:
                print(f"  fund[{i}] FAIL status={rec.get('status') if rec else 'timeout'}")
                break
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
            else:
                print(f"  fund[{i}] ERROR: {e}")
    if (i + 1) % 20 == 0:
        print(f"  Funded: {ok_fund}/{i + 1}")
print(f"  Total funded: {ok_fund}/{NUM_ACCOUNTS}")

# 4b. 余额闸门：FROM 侧收据 status=0 只代表 funder 扣款确认，账户的入账（同分片跨 pool
#     贷记）在高负载下会滞后或丢失——收据成功但 balance 仍为 0。若不校验直接进 prefund，
#     零余额账户会读不到 nonce → 10007(kTxUserNonceInvalid)、账户未落节点 → address invalid，
#     失败交易再触发 SDK 30s nonce 轮询风暴拖垮同批收据 → 100010。
#     这里按链上真实余额校验：并发读余额，对未入账账户串行补发（逐笔读链上 nonce、等收据、
#     再轮询账户余额确认到账），全部到账才放行。
print(f"\n[4b/6] Verifying on-chain balances, repairing under-funded accounts...")
time.sleep(8)  # 先给滞后的贷记一点结算时间，避免误判 + 重复充值

FUND_MIN_OK = FUND_AMOUNT // 2  # 账户余额非 0(=FUND_AMOUNT) 即成功；半额阈值干净分离两态

def _chain_balance(addr):
    try:
        return client.get_balance(addr)
    except Exception:
        return 0

def _find_underfunded():
    missing = []
    with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as ex:
        futs = {ex.submit(_chain_balance, a["address"]): (i, a) for i, a in enumerate(accounts)}
        for fut in as_completed(futs):
            i, a = futs[fut]
            if fut.result() < FUND_MIN_OK:
                missing.append((i, a))
    return sorted(missing)

def _refund_serial(missing):
    """串行补发：send_transaction_auto 内部管理 nonce，逐笔等收据再发下一笔。"""
    repaired = 0
    for i, acc in missing:
        addr = acc["address"]
        txh = client.send_transaction_auto(FUNDER_KEY, addr, StepType.kNormalFrom,
                                           amount=FUND_AMOUNT)
        client.wait_for_receipt(txh, timeout=60)
        for _ in range(30):  # 等账户余额真正出现（跨 pool 贷记可能滞后）
            if _chain_balance(addr) >= FUND_MIN_OK:
                repaired += 1
                break
            time.sleep(1)
    return repaired

for _round in range(5):
    missing = _find_underfunded()
    if not missing:
        print(f"  All {NUM_ACCOUNTS} accounts funded on-chain.")
        break
    print(f"  Round {_round + 1}: {len(missing)} under-funded, repairing serially...")
    _refund_serial(missing)
else:
    still = _find_underfunded()
    if still:
        print(f"  WARN: {len(still)} accounts still under-funded after 5 repair rounds: "
              f"{[i for i, _ in still]}")

# 5. Prefund all on contract — 每个账户独立发送方，可真正并发
print(f"\n[5/6] Prefunding {NUM_ACCOUNTS} accounts on contract ({PREFUND_AMOUNT})  [batch={BATCH_WORKERS}]...")
time.sleep(5)

def _send_prefund(args):
    i, acc = args
    c = w3.contract(abi=abi, bytecode=bytecode, address=contract_addr, sender_address=acc["address"])
    rec = c.prefund(PREFUND_AMOUNT, acc["private_key"])
    return i, rec, f"prefund[{i}]"

ok_pf = 0
with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as ex:
    for idx, rec, label in ex.map(_send_prefund, enumerate(accounts)):
        if rec and rec.get("status") == 0:
            ok_pf += 1
        elif rec and rec.get("status") not in (10003,):
            print(f"  {label} FAIL status={rec.get('status')}")
        if (idx + 1) % 20 == 0:
            print(f"  Prefunded {ok_pf}/{idx + 1}")
print(f"  Total prefunded: {ok_pf}/{NUM_ACCOUNTS}")

# 6. Test CreateNewItem — 每个账户独立发送方，真正并发
print(f"\n[6/6] Testing CreateNewItem x {NUM_ACCOUNTS}  [batch={BATCH_WORKERS}]...")
time.sleep(5)

now_ms = int(time.time() * 1000)

def _send_create(args):
    i, acc = args
    c = w3.contract(abi=abi, bytecode=bytecode, address=contract_addr, sender_address=acc["address"])
    item_hash = secrets.token_bytes(32)
    t = now_ms + i
    method = c.functions.CreateNewItem(item_hash, f"item_{i}".encode(), 100000 + i, t, t + 86400000)
    rec = method.transact(acc["private_key"], prefund=CALL_PREFUND)
    return i, rec, f"call[{i}]"

ok_call = 0
with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as ex:
    for idx, rec, label in ex.map(_send_create, enumerate(accounts)):
        if rec and rec.get("status") == 0:
            ok_call += 1
        elif rec and rec.get("status") not in (10003,):
            print(f"  {label} FAIL status={rec.get('status')}")
        if (idx + 1) % 20 == 0:
            print(f"  CreateNewItem: {ok_call}/{idx + 1} OK")
print(f"  Total CreateNewItem OK: {ok_call}/{NUM_ACCOUNTS}")

# Results
print("\n" + "=" * 60)
print("  DEPLOYMENT RESULTS")
print("=" * 60)
print(f"  Contract Address : {contract_addr}")
print(f"  Accounts Funded  : {ok_fund}/{NUM_ACCOUNTS}")
print(f"  Accounts Prefund : {ok_pf}/{NUM_ACCOUNTS}")
print(f"  CreateNewItem OK : {ok_call}/{NUM_ACCOUNTS}")
print("=" * 60)

if ok_call < NUM_ACCOUNTS * 0.9:
    print("FATAL: Less than 90% accounts succeeded!")
    sys.exit(1)

# Save
result = {
    "contract_address": contract_addr,
    "deployer_address": funder_addr,
    "accounts": accounts,
}
with open(OUTPUT_FILE, "w") as f:
    json.dump(result, f, indent=2)

print(f"\n  Contract: {contract_addr}")
print(f"\n  {NUM_ACCOUNTS} Account Private Keys:")
for acc in accounts:
    print(f"    [{acc['index']:3d}] {acc['private_key']}  ({acc['address']})")
print(f"\n  Saved to {OUTPUT_FILE}")
