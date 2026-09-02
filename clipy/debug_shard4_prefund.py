#!/usr/bin/env python3
import sys, time, secrets
sys.path.insert(0, '/root/seth/clipy')
from test_exchange_contract import (
    fund_account, gen_key_for_shard, calc_shard_id, w3_for_shard,
    CONTRACT_PREFUND, ITEM_PRICE, HOST,
)
from seth_sdk import compile_and_link, StepType

FUNDER_KEY = open('/root/nodes/s3_1/init_accounts3').readline().split()[0]

shard = 4
k, a = gen_key_for_shard(shard)
print('seller', a[:16], 'shard', calc_shard_id(a))
fund_account(a)
bal = w3_for_shard(shard).client.get_balance(a)
print('balance', bal)

src = open('/root/seth/src/contract/tests/contracts/exchange.sol', encoding='utf-8').read()
bc, abi = compile_and_link(src, 'Exchange')
ex = w3_for_shard(shard).seth.contract(abi=abi, bytecode=bc)
salt = secrets.token_hex(31) + '00'
ex.deploy({'from': a, 'salt': salt, 'args': [], 'amount': 0}, k)
print('deploy status', ex.deploy_receipt.get('status'), 'addr', ex.address)

r = ex.prefund(CONTRACT_PREFUND, k)
print('prefund status', r.get('status'), r.get('msg'))
for i in range(60):
    pf = ex.get_prefund(a)
    print(f'poll {i}: prefund={pf}')
    if pf >= CONTRACT_PREFUND:
        break
    time.sleep(2)
else:
    print('PREFUND TIMEOUT')
    sys.exit(1)

item_hash = secrets.token_bytes(32)
item_info = b'test_item'
start_ms = int(time.time() * 1000)
end_ms = start_ms + 86400000
r2 = ex.functions.CreateNewItem(item_hash, item_info, ITEM_PRICE, start_ms, end_ms).transact(k)
print('CreateNewItem', r2.get('status'), r2.get('msg'))
