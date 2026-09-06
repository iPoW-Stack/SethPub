#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

from eth_abi import encode as eth_abi_encode
from eth_utils import to_checksum_address

CONTRACTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CONTRACTS_DIR))

from deploy_shardora import (  # noqa: E402
    ShardoraClient,
    compile_contract_file,
    deploy_contract,
    encode_call,
)
from request_withdraw_to_solana_from_shardora import (  # noqa: E402
    query_contract_raw,
    _extract_hex_output,
    _decode_uint256_word,
)


def q_u256(host: str, port: int, from_hex: str, addr_hex: str, sig: str) -> int | None:
    raw = query_contract_raw(host, port, from_hex, addr_hex, encode_call(sig, [], []))
    out = _extract_hex_output(raw or "")
    if not out:
        return None
    return _decode_uint256_word(out, 0)


def main() -> int:
    host = os.environ.get("SHARDORA_HOST", "35.197.170.240")
    port = int(os.environ.get("SHARDORA_PORT", "23001"))
    deployer_pk = (os.environ.get("DEPLOYER_PRIVATE_KEY") or os.environ.get("RELAYER_PRIVATE_KEY") or "").strip()
    if not deployer_pk:
        print("ERROR: set DEPLOYER_PRIVATE_KEY or RELAYER_PRIVATE_KEY", file=sys.stderr)
        return 1
    if not deployer_pk.startswith("0x"):
        deployer_pk = "0x" + deployer_pk

    client = ShardoraClient(host, port)
    deployer_addr = client.get_address(deployer_pk)
    print("deployer:", "0x" + deployer_addr, "balance:", client.get_balance(deployer_addr))

    c_pool = compile_contract_file("ProbePool.sol")
    c_treasury = compile_contract_file("ProbeTreasury.sol")
    c_bridge = compile_contract_file("ProbeBridge.sol")

    pool_ctor = eth_abi_encode(["uint256", "uint256"], [10_000, 10_000]).hex()
    pool_addr = deploy_contract(
        client,
        deployer_pk,
        deployer_addr,
        c_pool["bin"] + pool_ctor,
        "acf1",
        10_000_000,
        5_000_000,
        "ProbePool",
    )

    treasury_ctor = eth_abi_encode(["address"], [to_checksum_address("0x" + pool_addr)]).hex()
    treasury_addr = deploy_contract(
        client,
        deployer_pk,
        deployer_addr,
        c_treasury["bin"] + treasury_ctor,
        "acf2",
        10_000_000,
        5_000_000,
        "ProbeTreasury",
    )

    bridge_ctor = eth_abi_encode(["address"], [to_checksum_address("0x" + treasury_addr)]).hex()
    bridge_addr = deploy_contract(
        client,
        deployer_pk,
        deployer_addr,
        c_bridge["bin"] + bridge_ctor,
        "acf3",
        10_000_000,
        5_000_000,
        "ProbeBridge",
    )

    print("pool:", "0x" + pool_addr)
    print("treasury:", "0x" + treasury_addr)
    print("bridge:", "0x" + bridge_addr)

    tx_set = client.send_transaction_auto(
        deployer_pk,
        treasury_addr,
        amount=0,
        gas_limit=8_000_000,
        gas_price=1,
        step=8,
        input_hex=encode_call("setBridge(address)", ["address"], [to_checksum_address("0x" + bridge_addr)]),
    )
    ok_set, st_set = client.wait_for_receipt(tx_set, 300)
    print("setBridge tx=", tx_set, "receipt=", ok_set, st_set)

    b_rs = q_u256(host, port, deployer_addr, pool_addr, "reserveSHARDORA()")
    b_ru = q_u256(host, port, deployer_addr, pool_addr, "reserveUSDC()")
    b_req = q_u256(host, port, deployer_addr, bridge_addr, "totalRequests()")
    b_sw = q_u256(host, port, deployer_addr, treasury_addr, "totalSwaps()")
    print("before pool=", b_rs, b_ru, "bridgeReq=", b_req, "treasurySwaps=", b_sw)

    tx_req = client.send_transaction_auto(
        deployer_pk,
        bridge_addr,
        amount=2,
        gas_limit=8_000_000,
        gas_price=1,
        step=8,
        input_hex=encode_call("request(uint256)", ["uint256"], [1]),
    )
    ok_req, st_req = client.wait_for_receipt(tx_req, 300)
    print("request tx=", tx_req, "receipt=", ok_req, st_req)

    a_rs = q_u256(host, port, deployer_addr, pool_addr, "reserveSHARDORA()")
    a_ru = q_u256(host, port, deployer_addr, pool_addr, "reserveUSDC()")
    a_req = q_u256(host, port, deployer_addr, bridge_addr, "totalRequests()")
    a_sw = q_u256(host, port, deployer_addr, treasury_addr, "totalSwaps()")
    a_last = q_u256(host, port, deployer_addr, bridge_addr, "lastOut()")
    print("after  pool=", a_rs, a_ru, "bridgeReq=", a_req, "treasurySwaps=", a_sw, "bridgeLastOut=", a_last)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

