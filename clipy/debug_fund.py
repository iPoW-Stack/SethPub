#!/usr/bin/env python3
import sys, time
sys.path.insert(0, "/root/seth/clipy")
from test_exchange_contract import *
from seth_sdk import StepType

FUNDER_KEY = "f1757118b56a13dbb96c41be76b6368b95f78ad07c5d2b04a2e7e1972cd33ae5"
HOST = "192.168.25.129"
import test_exchange_contract as tec
tec.HOST = HOST
tec.FUNDER_KEY = FUNDER_KEY
tec._W3_CACHE.clear()

fa = get_address(FUNDER_KEY)
print("funder", fa, query_account_on_shard(3, fa))
k, a = gen_key_for_shard(4)
print("target", a, "shard", calc_shard_id(a))

# method 1: SDK
fc = w3_funder().client
txh = fc.send_transaction_auto(FUNDER_KEY, a, StepType.kNormalFrom, amount=50_000_000)
print("sdk txh", txh)
r = fc.wait_for_receipt(txh, timeout=60)
print("sdk receipt", r.get("status"), r.get("msg"))
time.sleep(10)
print("balance", tec.query_account_home(a))

# method 2: send_ecdsa_tx
k2, a2 = tec.gen_key_for_shard(4)
info = tec.query_account_on_shard(3, fa)
nonce = int(info.get("nonce", 0)) + 1
txh2, cl, ok = tec.send_ecdsa_tx(FUNDER_KEY, a2, int(StepType.kNormalFrom), nonce, amount=50_000_000)
print("ecdsa send", ok, txh2)
recs = tec.batch_wait_receipts({a2: (txh2, cl)}, timeout=60)
print("ecdsa receipt", recs)
time.sleep(10)
print("balance2", tec.query_account_home(a2))
