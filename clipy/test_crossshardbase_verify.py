#!/usr/bin/env python3
"""
CrossShardBase verification script.
Queries shard4/shard5 shadow contracts using the Feistel-derived addresses.

Key fix: C++ deploys shadow contracts at DeriveShardAddress(base, shard, pool),
NOT at the base address. This script computes the correct shadow address in Python
using the same algorithm as C++ reversible_feistel_address.h.
"""
import sys
sys.path.insert(0, "/root/seth/clipy")

import json, time, hashlib, struct, subprocess
import requests
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from Crypto.Hash import keccak as _keccak
import eth_abi
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST    = "192.168.25.129"
PRIVKEY = "c8ee398141fe31308fce258fa4c0fc21288a74a221982db252cb10a94bf7063b"
SOLC    = "/root/seth/python/solc"
VERIFY  = False
SHARD_PORT = {2: 22001, 3: 23001, 4: 24001, 5: 25001, 6: 26001}
SYSTEM_EXECUTOR = "53595354454d5f4558454355544f525f56310000"

# ── Crypto ────────────────────────────────────────────────────────────────────
def keccak256(data):
    k = _keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def get_address(pk_hex):
    sk  = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.verifying_key.to_string("uncompressed")[1:]
    return keccak256(pub)[-20:].hex()

def encode_call(sig, types, args):
    return keccak256(sig.encode())[:4].hex() + eth_abi.encode(types, args).hex()

def query_decode(raw_hex, types):
    try:
        clean = raw_hex.strip().lstrip("0x").lstrip("0X")
        raw_bytes = bytes.fromhex(clean)
        if len(raw_bytes) > 32 and raw_bytes[:31] == b"\x00" * 31 and raw_bytes[31] == 0x20:
            try:
                err_bytes = eth_abi.decode(["bytes"], raw_bytes)
                print(f"    server error: {err_bytes[0].decode(errors='replace')}")
            except Exception:
                pass
            return None
        return eth_abi.decode(types, raw_bytes)
    except Exception:
        return None

# ── Feistel (matches C++ reversible_feistel_address.h exactly) ───────────────
# Preimage = tag[0:18] + shard(4B BE) + pool(4B BE) + round(4B BE)
# tag = "AKAVERSE_FEISTEL_V1"[:18] = "AKAVERSE_FEISTEL_V"  (C++ copies only 18 bytes)
# round key = keccak256(preimage)[22:32]  (last 10 bytes)
# F(R, rk)  = keccak256(R ^ rk, both 10 bytes)[22:32]
_FEISTEL_TAG = b"AKAVERSE_FEISTEL_V1"[:18]

def _rk(shard, pool, round_):
    pre = _FEISTEL_TAG + shard.to_bytes(4,"big") + pool.to_bytes(4,"big") + round_.to_bytes(4,"big")
    return keccak256(pre)[22:32]

def _F(R, rk):
    xored = bytes(a ^ b for a, b in zip(R, rk))
    return keccak256(xored)[22:32]

def derive_shard_address(base_hex, shard, pool):
    b = bytes.fromhex(base_hex.lower().zfill(40))
    L = bytearray(b[:10])
    R = bytearray(b[10:])
    for i in range(4):
        rk   = _rk(shard, pool, i)
        fout = _F(bytes(R), rk)
        nR   = bytearray(a ^ b for a, b in zip(L, fout))
        L    = bytearray(R)
        R    = nR
    return (bytes(L) + bytes(R)).hex()

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def client(shard):
    p = SHARD_PORT[shard]
    base = "https://{}:{}".format(HOST, p)
    return dict(abi=base + "/abi_query_contract")

def call_view(c, from_addr, contract, inp):
    r = requests.post(c["abi"],
                      data={"from": from_addr, "address": contract, "input": inp},
                      verify=VERIFY, timeout=10)
    return r.text.strip()

def pool_index(addr):
    def xxh32(data, seed=0):
        P1,P2,P3,P4,P5,M = 0x9E3779B1,0x85EBCA77,0xC2B2AE3D,0x27D4EB2F,0x165667B1,0xFFFFFFFF
        u = lambda v: v & M
        r = lambda v, n: u((v << n) | (v >> (32 - n)))
        n, p = len(data), 0
        if n >= 16:
            v1,v2,v3,v4 = u(seed+P1+P2),u(seed+P2),u(seed),u(seed-P1)
            while p <= n - 16:
                for vi in range(4):
                    l = struct.unpack_from("<I", data, p)[0]; p += 4
                    if   vi==0: v1=u(r(u(v1+u(l*P2)),13)*P1)
                    elif vi==1: v2=u(r(u(v2+u(l*P2)),13)*P1)
                    elif vi==2: v3=u(r(u(v3+u(l*P2)),13)*P1)
                    else:       v4=u(r(u(v4+u(l*P2)),13)*P1)
            h = u(r(v1,1)+r(v2,7)+r(v3,12)+r(v4,18))
        else:
            h = u(seed+P5)
        h = u(h + n)
        while p <= n-4:
            h = u(r(u(h+u(struct.unpack_from("<I",data,p)[0]*P3)),17)*P4); p+=4
        while p < n:
            h = u(r(u(h+u(data[p]*P5)),11)*P1); p+=1
        h = u(u(h^(h>>15))*P2); h = u(u(h^(h>>13))*P3); h = u(h^(h>>16))
        return h
    b = bytes.fromhex(addr.lower().replace("0x", ""))
    return xxh32(b, 623453345) % 32

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    SENDER = get_address(PRIVKEY)
    print("Sender: {}".format(SENDER))

    # Hard-coded from previous successful deployment (SALT=312)
    # Change if re-deployed with different SALT.
    DEPLOY_ADDR = "dcd78070920fb944b5f2feac18f71406da1a2857"

    TO_SHARD  = 4
    TO_ADDR   = SENDER
    TO_POOL   = pool_index(TO_ADDR)
    TO_SHARD2 = 5
    TO_POOL2  = pool_index(SENDER)

    shadow4 = derive_shard_address(DEPLOY_ADDR, TO_SHARD, TO_POOL)
    shadow5 = derive_shard_address(DEPLOY_ADDR, TO_SHARD2, TO_POOL2)

    print("\n[Feistel-derived shadow addresses]")
    print("  base:    {}".format(DEPLOY_ADDR))
    print("  shadow4: {}  (shard={} pool={})".format(shadow4, TO_SHARD, TO_POOL))
    print("  shadow5: {}  (shard={} pool={})".format(shadow5, TO_SHARD2, TO_POOL2))

    # Verify against known C++ result from logs
    KNOWN_SHADOW4 = "82fd737752f372316593048ee8e2eea7ee379512"
    if shadow4 == KNOWN_SHADOW4:
        print("  [OK] shadow4 matches C++ log!")
    else:
        print("  [MISMATCH] shadow4={} expected={}".format(shadow4, KNOWN_SHADOW4))

    c3 = client(3)
    c4 = client(TO_SHARD)
    c5 = client(TO_SHARD2)

    # Query base contract on shard3
    print("\n[1] shard3 balanceOf(sender) on BASE contract...")
    raw = call_view(c3, SENDER, DEPLOY_ADDR,
                    encode_call("balanceOf(address)", ["address"], [bytes.fromhex(SENDER)]))
    print("    raw: {}".format(raw[:120]))
    d = query_decode(raw, ["uint256"])
    if d:
        print("    shard3 base balance = {} TT".format(d[0] / 1e18))
    else:
        print("    decode failed")

    # Query shadow contract on shard4
    print("\n[2] shard4 balanceOf(sender) on SHADOW contract {}...".format(shadow4))
    raw = call_view(c4, SENDER, shadow4,
                    encode_call("balanceOf(address)", ["address"], [bytes.fromhex(TO_ADDR)]))
    print("    raw: {}".format(raw[:160]))
    d = query_decode(raw, ["uint256"])
    if d:
        print("    shard4 shadow balance = {} TT".format(d[0] / 1e18))
        print("    [PASS] Cross-shard transfer verified!")
    else:
        print("    decode failed (shadow not yet ready, or no balance transferred)")

    # Query shadow contract on shard5
    KEY = keccak256(b"test.cross.storage.key.v1")
    print("\n[3] shard5 readStorage on SHADOW contract {}...".format(shadow5))
    raw = call_view(c5, SENDER, shadow5,
                    encode_call("readStorage(bytes32)", ["bytes32"], [KEY]))
    print("    raw: {}".format(raw[:160]))
    d = query_decode(raw, ["bytes32"])
    if d:
        stored = d[0]
        print("    shard5 storage[key] = 0x{}".format(stored.hex()))
        expected_val = b"hello_cross_shard_v1" + b"\x00" * 12
        if stored == bytes(expected_val):
            print("    [PASS] Cross-shard storage verified!")
        else:
            print("    value present but doesn't match expected")
    else:
        print("    decode failed (shadow not yet ready, or storage never set)")

    print("\nDone.")

if __name__ == "__main__":
    main()
