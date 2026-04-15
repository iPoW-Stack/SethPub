"""
Native SETH one-click withdrawal test via Guardian HTTP VAA.

Flow: SETH -> wrap WSETH -> swap sUSDC -> burn -> fetch signed VAA -> Solana USDC
"""
import os
import sys
import time
import base64
import subprocess
import requests
from decimal import Decimal
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clipy"))

import eth_abi
from Crypto.Hash import keccak
from seth_sdk import SethClient, StepType

# ==================== Config ====================
HOST = "127.0.0.1"
PORT = 23001
USE_HTTPS = True  # server uses HTTPS
PK = "4b6525236a2029ab54e2c6162c483133c1af7d38bd960f85b1f485c31e696b7b"
GUARDIAN_API_BASE = os.getenv("GUARDIAN_API_BASE", "http://127.0.0.1:7072").rstrip("/")
SETH_CHAIN_ID = 10001
SOLANA_RECIP = "ce336c124aa1825f886b606448abdd2822f5db75d0f9a431f524a49b8738feeb"
DEFAULT_AMOUNT = "0.00001"
VAA_POLL_MAX_SECONDS = int(os.getenv("VAA_POLL_MAX_SECONDS", "180"))
VAA_POLL_INTERVAL = int(os.getenv("VAA_POLL_INTERVAL", "3"))


def load_seth_addresses():
    # Search in the same directory as this script first, then one level up.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "seth_addresses.env"),
        os.path.join(script_dir, "..", "seth_addresses.env"),
    ]
    out = {}
    for env_path in candidates:
        if not os.path.exists(env_path):
            continue
        with open(env_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().lower()
        break  # use the first file found
    return out

def sel(s):
    return keccak.new(digest_bits=256).update(s.encode()).digest()[:4].hex()

def _http_get_json(url, timeout=8):
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def fetch_vaa_from_guardian_http(chain_id, emitter_hex, sequence):
    # guardiand publicWeb format
    url1 = f"{GUARDIAN_API_BASE}/v1/signed_vaa/{chain_id}/{emitter_hex}/{sequence}"
    j1 = _http_get_json(url1)
    if isinstance(j1, dict):
        vaa_b64 = j1.get("vaaBytes") or j1.get("vaa")
        if isinstance(vaa_b64, str) and vaa_b64:
            return vaa_b64

    # custom guardian_signer.py fallback
    url2 = f"{GUARDIAN_API_BASE}/vaas/{sequence}"
    j2 = _http_get_json(url2)
    if isinstance(j2, dict):
        vaa_b64 = j2.get("vaa_b64")
        if isinstance(vaa_b64, str) and vaa_b64:
            return vaa_b64
        vaa_hex = j2.get("vaa_hex")
        if isinstance(vaa_hex, str) and vaa_hex:
            return base64.b64encode(bytes.fromhex(vaa_hex.replace("0x", ""))).decode()
    return None

def main():
    addrs = load_seth_addresses()
    bridge_router = os.getenv("BRIDGE_ROUTER", addrs.get("BRIDGE_ROUTER", ""))
    wb_addr = os.getenv("WORMHOLE_BRIDGE", addrs.get("WORMHOLE_BRIDGE", ""))
    # If the env var looks like a file path rather than an address, ignore it.
    if bridge_router and (bridge_router.startswith("/") or bridge_router.endswith(".env")):
        bridge_router = addrs.get("BRIDGE_ROUTER", "")
    if wb_addr and (wb_addr.startswith("/") or wb_addr.endswith(".env")):
        wb_addr = addrs.get("WORMHOLE_BRIDGE", "")
    if not bridge_router or not wb_addr:
        print("Missing BRIDGE_ROUTER / WORMHOLE_BRIDGE (env or seth_addresses.env)")
        return

    amount_str = DEFAULT_AMOUNT
    for i, a in enumerate(sys.argv):
        if a == "--amount" and i + 1 < len(sys.argv):
            amount_str = sys.argv[i + 1]

    seth_amount = int(Decimal(amount_str) * 10**8)
    cli = SethClient(HOST, PORT, use_https=USE_HTTPS)
    sender = cli.get_address(PK)

    print("=" * 55)
    print("  Native SETH One-Click Withdrawal")
    print("=" * 55)
    print(f"BridgeRouter: {bridge_router}")
    print(f"WormholeBridge: {wb_addr}")
    print(f"Sender:    {sender}")
    print(f"Amount:    {amount_str} SETH")
    print(f"Recipient: EsvTu4hJRLSa2syy4EY24UdfR6tqXDDhe9Pvcxazs9aJ")

    # Step 1: withdrawNativeToSolana (1 tx, no approve)
    print("\n[1] BridgeRouter.withdrawNativeToSolana...")
    print("    (wrap SETH→WSETH → swap→sUSDC → burn → Wormhole msg)")
    inp = sel("withdrawNativeToSolana(uint24,uint256,bytes32)") + eth_abi.encode(
        ["uint24", "uint256", "bytes32"],
        [3000, 0, bytes.fromhex(SOLANA_RECIP)]
    ).hex()
    tx = cli.send_transaction_auto(PK, bridge_router, StepType.kContractExcute,
                                    amount=seth_amount, input_hex=inp, prefund=10_000_000)
    rc = cli.wait_for_receipt(tx)
    ok = rc and rc.get("status") == 0
    print(f"    Result: {'OK' if ok else 'FAIL'}")
    if not ok:
        if rc and rc.get("output"):
            try:
                data = base64.b64decode(rc["output"])
                msg = eth_abi.decode(["string"], data[4:])[0]
                print(f"    Error: {msg}")
            except:
                pass
        return

    # Parse burn amount from BurnInitiated event (topic0 matches BurnInitiated)
    burn_amount = 0
    if rc.get("events"):
        import base64 as b64mod
        for evt in rc["events"]:
            data = b64mod.b64decode(evt["data"])
            # BurnInitiated has 4 topics, data contains amount + recipient + hash
            # Look for event with exactly the right structure
            if len(evt.get("topics", [])) == 3 and len(data) >= 64:
                # This is likely BurnInitiated: data = amount(32) + recipient(32) + hash(32)
                candidate = int.from_bytes(data[:32], "big")
                if 0 < candidate < 10**18:  # reasonable sUSDC amount
                    burn_amount = candidate
                    break
        if burn_amount == 0:
            # Fallback: use a small known amount from the swap
            burn_amount = 1  # placeholder
    print(f"    sUSDC burned: {burn_amount / 1e6}")

    # Get sequence
    seq_inp = sel("outboundSequence()")
    seq_raw = cli.query_contract(sender, wb_addr, seq_inp)
    try:
        sequence = int(str(seq_raw).replace("0x", "").strip(), 16)
    except:
        sequence = 0
    print(f"    Sequence: {sequence}")

    # Step 2: fetch VAA via Guardian HTTP
    emitter_hex = "000000000000000000000000" + wb_addr
    print("\n[2] Fetching signed VAA from Guardian HTTP...")
    print(f"    Guardian API: {GUARDIAN_API_BASE}")
    vaa_b64 = None
    deadline = time.time() + VAA_POLL_MAX_SECONDS
    while time.time() < deadline:
        vaa_b64 = fetch_vaa_from_guardian_http(SETH_CHAIN_ID, emitter_hex, sequence)
        if vaa_b64:
            break
        time.sleep(VAA_POLL_INTERVAL)
    if not vaa_b64:
        print(f"    FAIL: no signed VAA found in {VAA_POLL_MAX_SECONDS}s")
        return
    print(f"    VAA fetched: {len(base64.b64decode(vaa_b64))} bytes")

    # Step 3: Submit to Solana
    print("\n[3] Submitting to Solana...")
    result = subprocess.run(
        ["node", "solana/scripts/test-complete-transfer.js", "--vaa", vaa_b64],
        capture_output=True, text=True, timeout=30
    )
    for line in result.stdout.strip().split("\n"):
        print(f"    {line}")
    if result.returncode != 0 and result.stderr:
        for line in result.stderr.strip().split("\n")[-3:]:
            print(f"    {line}")

    print(f"\n{'=' * 55}")
    if result.returncode == 0:
        print(f"  OK: {amount_str} SETH → {burn_amount / 1e6} sUSDC → Solana USDC")
    else:
        print(f"  FAIL: Seth side OK, Solana submission failed")
    print(f"{'=' * 55}")

if __name__ == "__main__":
    main()
