#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

from eth_abi import encode as eth_abi_encode
from eth_utils import to_checksum_address

CONTRACTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CONTRACTS_DIR))

from deploy_seth import (  # noqa: E402
    SethClient,
    compile_contract_file,
    deploy_contract,
    encode_call,
)
from request_withdraw_to_solana_from_seth import (  # noqa: E402
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
    host = os.environ.get("SETH_HOST", "35.197.170.240")
    port = int(os.environ.get("SETH_PORT", "23001"))
    deployer_pk = (os.environ.get("DEPLOYER_PRIVATE_KEY") or os.environ.get("RELAYER_PRIVATE_KEY") or "").strip()
    if not deployer_pk:
        print("ERROR: set DEPLOYER_PRIVATE_KEY or RELAYER_PRIVATE_KEY", file=sys.stderr)
        return 1
    if not deployer_pk.startswith("0x"):
        deployer_pk = "0x" + deployer_pk

    client = SethClient(host, port)
    deployer_addr = client.get_address(deployer_pk)
    print("deployer:", "0x" + deployer_addr, "balance:", client.get_balance(deployer_addr))

    c_callee = compile_contract_file("ProbeCallee.sol")
    c_caller = compile_contract_file("ProbeCaller.sol")

    callee_salt = "abf1"
    caller_salt = "abf2"

    callee_addr = deploy_contract(
        client,
        deployer_pk,
        deployer_addr,
        c_callee["bin"],
        callee_salt,
        10_000_000,
        5_000_000,
        "ProbeCallee",
    )

    ctor = eth_abi_encode(["address"], [to_checksum_address("0x" + callee_addr)]).hex()
    caller_deploy = c_caller["bin"] + ctor
    caller_addr = deploy_contract(
        client,
        deployer_pk,
        deployer_addr,
        caller_deploy,
        caller_salt,
        10_000_000,
        5_000_000,
        "ProbeCaller",
    )

    print("callee:", "0x" + callee_addr)
    print("caller:", "0x" + caller_addr)

    b_hits = q_u256(host, port, deployer_addr, callee_addr, "totalHits()")
    b_last = q_u256(host, port, deployer_addr, callee_addr, "lastValue()")
    print("before totalHits=", b_hits, "lastValue=", b_last)

    tx1 = client.send_transaction_auto(
        deployer_pk,
        callee_addr,
        amount=2,
        gas_limit=8_000_000,
        gas_price=1,
        step=8,
        input_hex=encode_call("hit()", [], []),
    )
    ok1, st1 = client.wait_for_receipt(tx1, 300)
    print("direct hit tx=", tx1, "receipt=", ok1, st1)

    tx2 = client.send_transaction_auto(
        deployer_pk,
        caller_addr,
        amount=2,
        gas_limit=8_000_000,
        gas_price=1,
        step=8,
        input_hex=encode_call("forwardHit()", [], []),
    )
    ok2, st2 = client.wait_for_receipt(tx2, 300)
    print("forward hit tx=", tx2, "receipt=", ok2, st2)

    a_hits = q_u256(host, port, deployer_addr, callee_addr, "totalHits()")
    a_last = q_u256(host, port, deployer_addr, callee_addr, "lastValue()")
    a_fwds = q_u256(host, port, deployer_addr, caller_addr, "forwards()")
    a_fv = q_u256(host, port, deployer_addr, caller_addr, "lastForwardValue()")
    print("after totalHits=", a_hits, "lastValue=", a_last)
    print("caller forwards=", a_fwds, "lastForwardValue=", a_fv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

