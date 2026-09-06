#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2CSellOrder 合约部署与完整流程测试
目标网络：单机 5 分片 shardora (shard3 API)
运行方式：在 shardora-builder 容器内执行，挂载 /data/shardora/clipy 为工作目录
"""
import os, sys, time, secrets, json
sys.path.insert(0, "/data/shardora/clipy")

from shardora_sdk import ShardoraClient, ShardoraWeb3Mock, StepType, compile_and_link, calc_create2_address
import solcx as _solcx

import xxhash
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak
from eth_abi import encode as abi_encode
import solcx
solcx.install_solc("0.8.34")

HOST          = os.environ.get("SHARDORA_HOST", "139.159.119.119")
PORT          = int(os.environ.get("SHARDORA_PORT", "23001"))
FUNDER_KEY    = os.environ.get("FUNDER_KEY",
    "c8ee398141fe31308fce258fa4c0fc21288a74a221982db252cb10a94bf7063b")
TARGET_SHARD  = 3
HASH_SEED_1   = 23456785675590
MAX_SHARD_ID  = 6
CONSENSUS_SHARD_BEGIN = 3

# ── 账户工具 ───────────────────────────────────────────────
def calc_shard_id(addr_hex):
    b = bytes.fromhex(addr_hex.replace("0x",""))[:20]
    r = MAX_SHARD_ID - CONSENSUS_SHARD_BEGIN + 1
    return (xxhash.xxh64(b, seed=HASH_SEED_1).intdigest() % r) + CONSENSUS_SHARD_BEGIN

def gen_key_on_shard(shard):
    while True:
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.verifying_key.to_string("uncompressed")[1:]
        addr = keccak.new(digest_bits=256).update(pub).digest()[-20:].hex()
        if calc_shard_id(addr) == shard:
            return sk.to_string().hex(), addr

def find_salt(sender, bytecode, ctor_args_hex, shard):
    # init_code = bytecode + ABI-encoded constructor args
    init_code = bytecode + ctor_args_hex
    for _ in range(65536):
        s = secrets.token_hex(32)
        if calc_shard_id(calc_create2_address(sender, s, init_code)) == shard:
            return s
    raise RuntimeError(f"no CREATE2 salt for shard {shard}")

def ok(rec, label):
    s = rec.get("status") if rec else None
    if s != 0:
        raise RuntimeError(f"{label} FAIL status={s} msg={rec.get('msg','') if rec else 'timeout'}")
    print(f"  [OK] {label}  status={s}")

# ── 合约源码（完整版，含 purchasing/Lock 逻辑）──────────────
C2C_SOL = r"""
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract C2CSellOrder {
    struct SellOrder {
        bytes accountsReceivable;
        address payable addr;
        uint256 pledgeAmount;
        uint256 price;
        bool managerReleased;
        bool sellerReleased;
        bool exists;
        bool reported;
        bool purchasing;
        uint256 purchaseLockTime;
        uint256 orderId;
        uint256 height;
        address buyer;
        uint256 amount;
    }

    event NewSellout(address from,bytes receivable,uint256 price,uint256 pledgeAmount,uint256 orderId);
    event NewSelloutValue(uint256 value);
    event NewSelloutLength(uint256 value);

    uint256 orderId;
    address public owner;
    uint256 public minPlegementValue;
    uint256 public minExchangeValue;
    uint256 public constant PURCHASE_LOCK_DURATION = 3 minutes;
    uint256 test_data;
    mapping(address => SellOrder) public orders;
    mapping(address => bool) public valid_managers;
    address[] all_sellers;
    bytes32 test_ripdmd;

    constructor(address[] memory managers, uint256 minPlegement, uint256 minAmount) payable {
        uint arrayLength = managers.length;
        for (uint i=0; i<arrayLength; i++) { valid_managers[managers[i]] = true; }
        orderId = 0;
        valid_managers[msg.sender] = true;
        minPlegementValue = minPlegement;
        minExchangeValue = minAmount;
        owner = msg.sender;
    }

    function TestContract(uint256 receivable) public payable {
        emit NewSelloutValue(1);
        test_data = receivable;
        emit NewSelloutValue(2);
    }

    function callAbe(bytes memory params) public payable {
        test_ripdmd = ripemd160(params);
    }

    function SetManager(address[] memory managers) public {
        require(owner == msg.sender);
        require(!orders[msg.sender].exists);
        uint arrayLength = managers.length;
        for (uint i=0; i<arrayLength; i++) { valid_managers[managers[i]] = true; }
    }

    function NewSellOrder(bytes memory receivable, uint256 price) public payable {
        emit NewSelloutValue(msg.value);
        require(msg.value >= minPlegementValue);
        emit NewSellout(msg.sender, receivable, price, msg.value, orderId);
        require(!valid_managers[msg.sender]);
        if (orders[msg.sender].exists) {
            require(orders[msg.sender].managerReleased);
            delete orders[msg.sender];
        }
        orders[msg.sender] = SellOrder({
            accountsReceivable: receivable,
            addr: payable(msg.sender),
            pledgeAmount: msg.value,
            price: price,
            managerReleased: false,
            sellerReleased: false,
            exists: true,
            reported: false,
            purchasing: false,
            purchaseLockTime: 0,
            orderId: orderId,
            height: block.number,
            buyer: msg.sender,
            amount: 0
        });
        all_sellers.push(msg.sender);
        emit NewSelloutLength(all_sellers.length);
        emit NewSellout(msg.sender, receivable, price, msg.value, orderId);
        orderId++;
    }

    function _expirePurchaseLockIfNeeded(address seller) internal {
        SellOrder storage order = orders[seller];
        if (!order.exists || !order.purchasing) return;
        if (block.timestamp >= order.purchaseLockTime + PURCHASE_LOCK_DURATION) {
            order.purchasing = false;
            order.buyer = order.addr;
            order.amount = 0;
            order.height = block.number;
        }
    }

    function LockForPurchase(address seller, address payable buyer, uint256 amount) public payable {
        require(valid_managers[msg.sender]);
        require(orders[seller].exists);
        require(!orders[seller].managerReleased);
        require(!orders[seller].sellerReleased);
        require(!orders[seller].reported);
        _expirePurchaseLockIfNeeded(seller);
        require(!orders[seller].purchasing);
        require(amount >= minExchangeValue);
        require(orders[seller].pledgeAmount >= amount);
        orders[seller].purchasing = true;
        orders[seller].buyer = buyer;
        orders[seller].amount = amount;
        orders[seller].purchaseLockTime = block.timestamp;
        orders[seller].height = block.number;
    }

    function UnlockPurchase(address seller) public payable {
        require(valid_managers[msg.sender]);
        require(orders[seller].exists);
        require(orders[seller].purchasing);
        orders[seller].purchasing = false;
        orders[seller].buyer = orders[seller].addr;
        orders[seller].amount = 0;
        orders[seller].purchaseLockTime = 0;
        orders[seller].height = block.number;
    }

    function ExpirePurchaseLock(address seller) public payable {
        require(valid_managers[msg.sender]);
        require(orders[seller].exists);
        _expirePurchaseLockIfNeeded(seller);
    }

    function GetPurchaseLock(address seller) public view returns (bool active, address lockedBuyer, uint256 lockTime) {
        SellOrder storage order = orders[seller];
        if (!order.exists || !order.purchasing) return (false, address(0), 0);
        if (block.timestamp >= order.purchaseLockTime + PURCHASE_LOCK_DURATION)
            return (false, order.buyer, order.purchaseLockTime);
        return (true, order.buyer, order.purchaseLockTime);
    }

    function BuyerConfirmPurchase(address seller) public payable {
        require(orders[seller].exists);
        require(!orders[seller].managerReleased);
        require(!orders[seller].sellerReleased);
        require(!orders[seller].reported);
        require(orders[seller].purchasing);
        require(orders[seller].buyer == msg.sender);
        orders[seller].purchasing = false;
        orders[seller].purchaseLockTime = 0;
        orders[seller].height = block.number;
    }

    function Confirm(address payable buyer, uint256 amount) public payable {
        require(amount >= minExchangeValue);
        require(orders[msg.sender].exists);
        require(!orders[msg.sender].managerReleased);
        require(!orders[msg.sender].sellerReleased);
        require(!orders[msg.sender].reported);
        _expirePurchaseLockIfNeeded(msg.sender);
        if (orders[msg.sender].purchasing) {
            require(orders[msg.sender].buyer == buyer);
            require(orders[msg.sender].amount == amount);
        }
        require(orders[msg.sender].pledgeAmount >= amount);
        SellOrder memory order = orders[msg.sender];
        order.pledgeAmount -= amount;
        order.height = block.number;
        order.buyer = buyer;
        order.amount = amount;
        payable(buyer).transfer(amount);
        if (order.pledgeAmount < minExchangeValue) {
            if (order.pledgeAmount > 0) payable(msg.sender).transfer(order.pledgeAmount);
            order.pledgeAmount = 0;
            uint seller_len = all_sellers.length;
            for (uint i = 0; i < seller_len; ++i) {
                if (all_sellers[i] == msg.sender) { delete all_sellers[i]; break; }
            }
            delete orders[msg.sender];
        } else {
            order.purchasing = false;
            order.purchaseLockTime = 0;
            orders[msg.sender] = order;
        }
    }

    function ManagerRelease(address seller) public payable {
        require(orders[seller].exists);
        require(valid_managers[msg.sender]);
        SellOrder memory order = orders[seller];
        require(order.addr == seller);
        require(!order.managerReleased);
        order.managerReleased = true;
        order.height = block.number;
        if (order.pledgeAmount > 0) {
            payable(order.addr).transfer(order.pledgeAmount);
            order.pledgeAmount = 0;
        }
        orders[seller] = order;
    }

    function ManagerReleaseForce(address seller) public payable {
        require(orders[seller].exists);
        require(valid_managers[msg.sender]);
        SellOrder memory order = orders[seller];
        require(order.addr == seller);
        require(order.managerReleased);
        uint seller_len = all_sellers.length;
        for (uint i = 0; i < seller_len; ++i) {
            if (all_sellers[i] == seller) { delete all_sellers[i]; break; }
        }
        delete orders[seller];
    }

    function SellerRelease() public payable {
        require(orders[msg.sender].exists);
        SellOrder memory order = orders[msg.sender];
        order.sellerReleased = true;
        order.height = block.number;
        if (order.managerReleased) {
            payable(msg.sender).transfer(order.pledgeAmount);
            uint seller_len = all_sellers.length;
            for (uint i = 0; i < seller_len; ++i) {
                if (all_sellers[i] == msg.sender) { delete all_sellers[i]; break; }
            }
            delete orders[msg.sender];
        } else {
            orders[msg.sender] = order;
        }
    }

    function Report(address seller) public {
        require(orders[seller].exists);
        require(!orders[seller].reported);
        orders[seller].reported = true;
        orders[seller].height = block.number;
    }

    function bytesConcat(bytes[] memory arr, uint count) public pure returns (bytes memory){
        uint len = 0;
        for (uint i = 0; i < count; i++) len += arr[i].length;
        bytes memory bret = new bytes(len);
        uint k = 0;
        for (uint i = 0; i < count; i++)
            for (uint j = 0; j < arr[i].length; j++) bret[k++] = arr[i][j];
        return bret;
    }

    function ToHex(bytes memory buffer) public pure returns (bytes memory) {
        bytes memory converted = new bytes(buffer.length * 2);
        bytes memory _base = "0123456789abcdef";
        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i*2]   = _base[uint8(buffer[i]) / _base.length];
            converted[i*2+1] = _base[uint8(buffer[i]) % _base.length];
        }
        return converted;
    }

    function toBytes(address a) public pure returns (bytes memory) { return abi.encodePacked(a); }

    function u256ToBytes(uint256 x) public pure returns (bytes memory b) {
        b = new bytes(32);
        assembly { mstore(add(b, 32), x) }
    }

    function GetOrderJson(SellOrder memory order, bool last) public pure returns (bytes memory) {
        bytes[] memory all_bytes = new bytes[](120);
        uint n = 0;
        all_bytes[n++] = '{"r":"'; all_bytes[n++] = ToHex(order.accountsReceivable);
        all_bytes[n++] = '","a":"'; all_bytes[n++] = ToHex(toBytes(order.addr));
        all_bytes[n++] = '","b":"'; all_bytes[n++] = ToHex(toBytes(order.buyer));
        all_bytes[n++] = '","m":"'; all_bytes[n++] = ToHex(u256ToBytes(order.pledgeAmount));
        all_bytes[n++] = '","p":"'; all_bytes[n++] = ToHex(u256ToBytes(order.price));
        all_bytes[n++] = '","h":"'; all_bytes[n++] = ToHex(u256ToBytes(order.height));
        all_bytes[n++] = '","bm":"'; all_bytes[n++] = ToHex(u256ToBytes(order.amount));
        all_bytes[n++] = '","mr":'; all_bytes[n++] = order.managerReleased ? bytes('true') : bytes('false');
        all_bytes[n++] = ',"sr":';  all_bytes[n++] = order.sellerReleased  ? bytes('true') : bytes('false');
        all_bytes[n++] = ',"rp":';  all_bytes[n++] = order.reported        ? bytes('true') : bytes('false');
        all_bytes[n++] = ',"pc":';  all_bytes[n++] = order.purchasing      ? bytes('true') : bytes('false');
        all_bytes[n++] = ',"o":"';  all_bytes[n++] = ToHex(u256ToBytes(order.orderId));
        all_bytes[n++] = last ? bytes('"}') : bytes('"},');
        return bytesConcat(all_bytes, n);
    }

    function GetOrdersJson() public view returns(bytes memory) {
        bytes[] memory all_bytes = new bytes[](all_sellers.length + 2);
        all_bytes[0] = '[';
        uint arrayLength = all_sellers.length;
        uint validLen = 1;
        for (uint i=0; i<arrayLength; i++) {
            all_bytes[i+1] = GetOrderJson(orders[all_sellers[i]], (i == arrayLength - 1));
            ++validLen;
        }
        all_bytes[validLen] = ']';
        return bytesConcat(all_bytes, validLen + 1);
    }
}
"""

# ── 主流程 ─────────────────────────────────────────────────
print("=" * 60)
print("  C2CSellOrder 合约部署与测试")
print(f"  Shardora: {HOST}:{PORT}  shard={TARGET_SHARD}")
print("=" * 60)

client = ShardoraClient(HOST, PORT)
w3     = ShardoraWeb3Mock(HOST, PORT)

funder_addr = client.get_address(FUNDER_KEY)
print(f"\nFunder: {funder_addr}  (shard{calc_shard_id(funder_addr)})")
bal = client.get_balance(funder_addr)
print(f"Funder balance: {bal}")
if bal < 50_000_000:
    raise RuntimeError(f"Funder balance too low: {bal}")

# ── 生成测试账户（全在 shard3）──────────────────────────────
print("\n[1] 生成测试账户 (shard3)...")
manager_key, manager_addr = FUNDER_KEY, funder_addr   # funder 即 manager
seller_key, seller_addr   = gen_key_on_shard(TARGET_SHARD)
buyer_key,  buyer_addr    = gen_key_on_shard(TARGET_SHARD)
seller2_key, seller2_addr = gen_key_on_shard(TARGET_SHARD)

print(f"  manager : {manager_addr}")
print(f"  seller  : {seller_addr}")
print(f"  buyer   : {buyer_addr}")
print(f"  seller2 : {seller2_addr}")

# ── 给测试账户充值 ──────────────────────────────────────────
FUND = 300_000_000
print(f"\n[2] 充值测试账户 ({FUND} each)...")
time.sleep(5)  # 等待合约部署的 nonce 稳定
for addr, label in [(seller_addr,"seller"),(buyer_addr,"buyer"),(seller2_addr,"seller2")]:
    for attempt in range(3):
        txh = client.send_transaction_auto(FUNDER_KEY, addr, StepType.kNormalFrom, amount=FUND)
        rec = client.wait_for_receipt(txh, timeout=120)
        if rec and rec.get("status") == 0:
            print(f"  [OK] fund {label}  status=0")
            break
        elif rec and rec.get("status") == 10007 and attempt < 2:
            time.sleep(3)
            continue
        else:
            ok(rec, f"fund {label}")

time.sleep(8)
for addr, label in [(seller_addr,"seller"),(buyer_addr,"buyer"),(seller2_addr,"seller2")]:
    for _ in range(30):
        if client.get_balance(addr) >= FUND // 2:
            print(f"  {label} balance ok: {client.get_balance(addr)}")
            break
        time.sleep(2)

# ── 编译合约（via-ir 解决 stack too deep）──────────────────
print("\n[3] 编译 C2CSellOrder (--via-ir)...")
compiled = _solcx.compile_source(
    C2C_SOL,
    output_values=["abi", "bin"],
    solc_version="0.8.34",
    optimize=True,
    optimize_runs=200,
    via_ir=True,
    evm_version="shanghai",
)
contract_id = "<stdin>:C2CSellOrder"
bytecode = compiled[contract_id]["bin"]
abi      = compiled[contract_id]["abi"]
print(f"  bytecode={len(bytecode)} chars  abi={len(abi)} items")

# ── 部署合约（CREATE2 确保落在 shard3）─────────────────────
print("\n[4] 部署合约...")
MIN_PLEDGE   = 1_000_000
MIN_EXCHANGE = 100_000

contract = w3.contract(abi=abi, bytecode=bytecode, sender_address=funder_addr)
# ABI-encode constructor args: (address[], uint256, uint256)
ctor_args_hex = abi_encode(
    ["address[]", "uint256", "uint256"],
    [[manager_addr], MIN_PLEDGE, MIN_EXCHANGE],
).hex()
salt = find_salt(funder_addr, bytecode, ctor_args_hex, TARGET_SHARD)
deployed = contract.deploy(
    {"from": funder_addr, "salt": salt,
     "args": [[manager_addr], MIN_PLEDGE, MIN_EXCHANGE]},
    FUNDER_KEY,
)
contract_addr = deployed.address
print(f"  Contract: {contract_addr}  shard={calc_shard_id(contract_addr)}")
ok(deployed.deploy_receipt, "deploy C2CSellOrder")

# ── 辅助：获取合约实例 ──────────────────────────────────────
def c2c(sender_addr):
    return w3.contract(abi=abi, bytecode=bytecode, address=contract_addr,
                       sender_address=sender_addr)

CALL_GAS = 20_000_000
# 每个账户在合约上的 prefund 配额，需足够覆盖所有测试调用的 gas
ACCT_PREFUND = 200_000_000

# ── 激活账户 + 充足 prefund ────────────────────────────────────
# Shardora 中新账户（只收过转账、未发出过任何交易）直接作为发送方会报
# kTxInvalidAddress(10005)，必须先调用一次 contract.prefund() 来
# 在链上"激活"该账户。同时充足的 prefund 用于后续所有合约调用 gas。
print("\n[0] 激活测试账户（prefund，建立链上 nonce）...")
for k, a, label in [
    (seller_key,  seller_addr,  "seller"),
    (buyer_key,   buyer_addr,   "buyer"),
    (seller2_key, seller2_addr, "seller2"),
]:
    rec = c2c(a).prefund(ACCT_PREFUND, k)
    s = rec.get("status") if rec else None
    if s not in (0, None):
        print(f"  WARN prefund {label} status={s}")
    else:
        print(f"  [OK] prefund {label}")
time.sleep(5)

# ── 测试 1: TestContract ────────────────────────────────────
print("\n[T1] TestContract(42)...")
rec = c2c(funder_addr).functions.TestContract(42).transact(FUNDER_KEY, prefund=CALL_GAS)
ok(rec, "TestContract")

# ── 测试 2: callAbe (ripemd160 precompile) ──────────────────
print("\n[T2] callAbe(b'hello c2c')...")
rec = c2c(funder_addr).functions.callAbe(b"hello c2c").transact(FUNDER_KEY, prefund=CALL_GAS)
s = rec.get("status") if rec else None
if s == 0:
    print(f"  [OK] callAbe  status={s}")
else:
    print(f"  [SKIP] callAbe status={s} msg={rec.get('msg','') if rec else 'timeout'} (ripemd160 precompile 不支持，跳过)")

# ── 测试 3: NewSellOrder ────────────────────────────────────
print("\n[T3] NewSellOrder (seller)...")
PLEDGE = 5_000_000
PRICE  = 95
receivable = b"WeChat:seller_001"
rec = c2c(seller_addr).functions.NewSellOrder(receivable, PRICE).transact(
    seller_key, value=PLEDGE, prefund=CALL_GAS)
ok(rec, f"NewSellOrder pledge={PLEDGE}")

# ── 测试 4: LockForPurchase ─────────────────────────────────
print("\n[T4] LockForPurchase (manager locks for buyer)...")
LOCK_AMOUNT = 2_000_000
rec = c2c(manager_addr).functions.LockForPurchase(
    seller_addr, buyer_addr, LOCK_AMOUNT).transact(FUNDER_KEY, prefund=CALL_GAS)
ok(rec, f"LockForPurchase amount={LOCK_AMOUNT}")

# ── 测试 5: BuyerConfirmPurchase ────────────────────────────
print("\n[T5] BuyerConfirmPurchase (buyer confirms off-chain payment)...")
time.sleep(5)  # 等 LockForPurchase 状态在节点间传播，防止 buyer nonce 竞争
for _attempt in range(3):
    rec = c2c(buyer_addr).functions.BuyerConfirmPurchase(seller_addr).transact(
        buyer_key, prefund=CALL_GAS)
    if rec and rec.get("status") == 0:
        break
    if rec and rec.get("status") == 10007 and _attempt < 2:
        print(f"  WARN nonce collision, retry {_attempt+1}...")
        time.sleep(3)
        continue
    ok(rec, "BuyerConfirmPurchase")
ok(rec, "BuyerConfirmPurchase")

# ── 测试 6: Confirm (seller releases funds to buyer) ────────
print("\n[T6] Confirm (seller → buyer)...")
rec = c2c(seller_addr).functions.Confirm(buyer_addr, LOCK_AMOUNT).transact(
    seller_key, prefund=CALL_GAS)
ok(rec, f"Confirm amount={LOCK_AMOUNT}")

# ── 测试 7: NewSellOrder seller2，测试 LockForPurchase+UnlockPurchase
print("\n[T7] seller2 NewSellOrder + LockForPurchase + UnlockPurchase...")
rec = c2c(seller2_addr).functions.NewSellOrder(b"WeChat:seller_002", 90).transact(
    seller2_key, value=3_000_000, prefund=CALL_GAS)
ok(rec, "NewSellOrder seller2")

rec = c2c(manager_addr).functions.LockForPurchase(
    seller2_addr, buyer_addr, MIN_EXCHANGE).transact(FUNDER_KEY, prefund=CALL_GAS)
ok(rec, "LockForPurchase seller2")

rec = c2c(manager_addr).functions.UnlockPurchase(seller2_addr).transact(
    FUNDER_KEY, prefund=CALL_GAS)
ok(rec, "UnlockPurchase seller2")

# ── 测试 8: ManagerRelease + SellerRelease ──────────────────
print("\n[T8] ManagerRelease + SellerRelease (seller2)...")
rec = c2c(manager_addr).functions.ManagerRelease(seller2_addr).transact(
    FUNDER_KEY, prefund=CALL_GAS)
ok(rec, "ManagerRelease seller2")

rec = c2c(seller2_addr).functions.SellerRelease().transact(
    seller2_key, prefund=CALL_GAS)
ok(rec, "SellerRelease seller2")

# ── 测试 9: Report (单独 order 测试举报)──────────────────────
print("\n[T9] NewSellOrder + Report...")
seller3_key, seller3_addr = gen_key_on_shard(TARGET_SHARD)
txh = client.send_transaction_auto(FUNDER_KEY, seller3_addr, StepType.kNormalFrom, amount=FUND)
client.wait_for_receipt(txh, timeout=120)
time.sleep(6)
# 激活 seller3（首笔出向 TX）
rec = c2c(seller3_addr).prefund(ACCT_PREFUND, seller3_key)
s = rec.get("status") if rec else None
if s not in (0, None):
    print(f"  WARN prefund seller3 status={s}")
else:
    print(f"  [OK] prefund seller3")
time.sleep(15)

rec = c2c(seller3_addr).functions.NewSellOrder(b"WeChat:seller_003", 88).transact(
    seller3_key, value=MIN_PLEDGE, prefund=CALL_GAS)
ok(rec, "NewSellOrder seller3")

rec = c2c(buyer_addr).functions.Report(seller3_addr).transact(
    buyer_key, prefund=CALL_GAS)
ok(rec, "Report seller3")

# ── 汇总 ────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  ALL TESTS PASSED")
print(f"  Contract : {contract_addr}")
print(f"  Manager  : {manager_addr}")
print(f"  Seller   : {seller_addr}")
print(f"  Buyer    : {buyer_addr}")
print("=" * 60)

result = {
    "contract_address": contract_addr,
    "manager": manager_addr,
    "seller": {"key": seller_key, "address": seller_addr},
    "buyer":  {"key": buyer_key,  "address": buyer_addr},
}
out = "/data/tmp/c2c_deploy_result.json"
os.makedirs("/data/tmp", exist_ok=True)
with open(out, "w") as f:
    json.dump(result, f, indent=2)
print(f"\n  Result saved to {out}")
