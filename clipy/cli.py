import struct
import requests
import hashlib
import json
import time
from Crypto.Hash import keccak
# Using pure Python ecdsa library
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_string_canonize

class SethClient:
    def __init__(self, host, port):
        self.base_url = f"http://{host}:{port}"
        self.tx_url = f"{self.base_url}/transaction"
        self.query_url = f"{self.base_url}/query_account"

    def _uint64_to_bytes(self, val):
        return struct.pack('<Q', val)

    def _hex_to_bytes(self, hex_str):
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        return bytes.fromhex(hex_str)

    def _derive_address_from_pubkey(self, pubkey_bytes_no_prefix):
        """
        Derive address from public key.
        Assumption: Similar to Ethereum rules -> Last 20 bytes of Keccak256(Pubkey_64bytes).
        If your chain rules differ, modify this.
        """
        k = keccak.new(digest_bits=256)
        k.update(pubkey_bytes_no_prefix)
        digest = k.digest()
        # Take the last 20 bytes as the address
        address_bytes = digest[-20:]
        return address_bytes.hex()

    def get_latest_nonce(self, address_hex):
        """
        Query account info and get the latest Nonce
        """
        print(f"[Client] Querying nonce for address: {address_hex}")
        try:
            # Construct request, server QueryAccount expects 'address' parameter
            data = {"address": address_hex}
            resp = requests.post(self.query_url, data=data, timeout=5)

            if resp.status_code != 200:
                print(f"[Error] Query failed: {resp.text}")
                return 0 # Account might not exist, default to 0

            # Parse returned JSON
            # Server response example: {"address": "...", "balance": 1000, "nonce": 5, ...}
            # Note: Protobuf JSON fields might be omitted if they are default values, need handling
            try:
                account_info = resp.json()
                # If empty object or no nonce field, it's a new account, return 0
                nonce = int(account_info.get("nonce", 0))
                print(f"[Client] Current Nonce on chain: {nonce}")
                return nonce
            except json.JSONDecodeError:
                print(f"[Client] Failed to parse JSON, assuming new account. Resp: {resp.text}")
                return 0

        except Exception as e:
            print(f"[Error] Get nonce error: {e}")
            return 0

    def compute_hash(self, nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, step,
                     contract_code='', input_hex='', prepayment=0, key='', val=''):
        msg = bytearray()
        msg.extend(self._uint64_to_bytes(nonce))
        msg.extend(self._hex_to_bytes(pubkey_hex))
        msg.extend(self._hex_to_bytes(to_hex))
        msg.extend(self._uint64_to_bytes(amount))
        msg.extend(self._uint64_to_bytes(gas_limit))
        msg.extend(self._uint64_to_bytes(gas_price))
        msg.extend(self._uint64_to_bytes(step))
        if contract_code: msg.extend(self._hex_to_bytes(contract_code))
        if input_hex: msg.extend(self._hex_to_bytes(input_hex))
        if prepayment > 0: msg.extend(self._uint64_to_bytes(prepayment))
        if key:
            msg.extend(key.encode('utf-8'))
            if val: msg.extend(val.encode('utf-8'))

        k = keccak.new(digest_bits=256)
        k.update(msg)
        return k.digest()

    def send_transaction_auto(self, private_key_hex, to_hex, amount=0,
                              gas_limit=50000, gas_price=1, step=0, shard_id=0,
                              contract_code='', input_hex='', prepayment=0,
                              key='', val=''):
        """
        Automatic Workflow:
        1. Derive public key and address from private key
        2. Query the latest Nonce for this address from the network
        3. Nonce + 1
        4. Sign and send
        """

        # --- 1. Prepare Keys ---
        if private_key_hex.startswith('0x'):
            private_key_hex = private_key_hex[2:]

        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        vk = sk.verifying_key

        # Export uncompressed public key (65 bytes: 04 + X + Y)
        pubkey_bytes_full = vk.to_string("uncompressed")
        pubkey_hex = pubkey_bytes_full.hex()

        # Derive address (Used to query Nonce)
        # Get raw public key bytes without '04' prefix (64 bytes)
        pubkey_bytes_raw = pubkey_bytes_full[1:]
        my_address_hex = self._derive_address_from_pubkey(pubkey_bytes_raw)

        # --- 2. Get and Increment Nonce ---
        current_nonce = self.get_latest_nonce(my_address_hex)
        next_nonce = current_nonce + 1
        print(f"[Client] Using Next Nonce: {next_nonce}")

        # --- 3. Compute Hash ---
        tx_hash = self.compute_hash(
            next_nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, step,
            contract_code, input_hex, prepayment, key, val
        )

        # --- 4. Sign ---
        signature = sk.sign_digest_deterministic(
            tx_hash,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_string_canonize
        )
        r_bytes = signature[0:32]
        s_bytes = signature[32:64]

        # Simple Recovery ID handling (Default 0, retry 1 on failure)
        v_byte = 0

        # --- 5. Send Request ---
        data = {
            "nonce": str(next_nonce),
            "pubkey": pubkey_hex,
            "to": to_hex,
            "amount": str(amount),
            "gas_limit": str(gas_limit),
            "gas_price": str(gas_price),
            "shard_id": str(shard_id),
            "type": str(step),
            "sign_r": r_bytes.hex(),
            "sign_s": s_bytes.hex(),
            "sign_v": str(v_byte)
        }

        # Optional parameters
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment > 0: data["pepay"] = str(prepayment)
        if key: data["key"] = key
        if val: data["val"] = val

        print("[Client] Sending Transaction...")
        try:
            resp = requests.post(self.tx_url, data=data, timeout=5)
            print(f"[Server Response] {resp.status_code}: {resp.text}")

            # Auto retry V=1
            if "SignatureInvalid" in resp.text or "verify signature failed" in resp.text:
                print("[Client] Signature rejected (V=0), retrying with V=1...")
                data["sign_v"] = "1"
                resp = requests.post(self.tx_url, data=data, timeout=5)
                print(f"[Server Response (Retry)] {resp.status_code}: {resp.text}")

        except Exception as e:
            print(f"[Error] Network error: {e}")

# ==========================================
# Run Test
# ==========================================
if __name__ == "__main__":
    HOST = "136.110.63.32"
    PORT = 23014

    # Sender private key
    MY_PRIVATE_KEY = "c75f8d9b2a6bc0fe68eac7fef67c6b6f7c4f85163d58829b59110ff9e9210848"

    # Receiver address
    TO_ADDR = "1234567890abcdef1234567890abcdef12345678"

    client = SethClient(HOST, PORT)

    # Call automatic Nonce interface
    client.send_transaction_auto(
        private_key_hex=MY_PRIVATE_KEY,
        to_hex=TO_ADDR,
        amount=5000
    )
