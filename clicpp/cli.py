# pip install requests coincurve pycryptodome
import struct
import requests
from Crypto.Hash import keccak
from coincurve import PrivateKey, PublicKey

class SethClient:
    def __init__(self, host, port):
        self.url = f"http://{host}:{port}/transaction"

    def _uint64_to_bytes(self, val):
        # Corresponds to C++: std::string((char*)&val, sizeof(val))
        # Uses Little Endian (<) 64-bit unsigned integer (Q)
        return struct.pack('<Q', val)

    def _hex_to_bytes(self, hex_str):
        return bytes.fromhex(hex_str)

    def compute_hash(self, nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, step, 
                     contract_code='', input_hex='', prepayment=0, key='', val=''):
        """
        Strictly replicates the serialization logic of the server-side C++ GetTxMessageHash
        """
        msg = bytearray()
        
        # 1. nonce (uint64)
        msg.extend(self._uint64_to_bytes(nonce))
        
        # 2. pubkey (bytes)
        # Server expects hex string, decodes it internally, then appends
        msg.extend(self._hex_to_bytes(pubkey_hex))
        
        # 3. to (bytes)
        msg.extend(self._hex_to_bytes(to_hex))
        
        # 4. amount (uint64)
        msg.extend(self._uint64_to_bytes(amount))
        
        # 5. gas_limit (uint64)
        msg.extend(self._uint64_to_bytes(gas_limit))
        
        # 6. gas_price (uint64)
        msg.extend(self._uint64_to_bytes(gas_price))
        
        # 7. step (uint64)
        # Note: Although the server receives uint32, it uses uint64 conversion during serialization
        msg.extend(self._uint64_to_bytes(step))
        
        # 8. contract_code (bytes)
        if contract_code:
            msg.extend(self._hex_to_bytes(contract_code))
            
        # 9. input (bytes)
        if input_hex:
            msg.extend(self._hex_to_bytes(input_hex))
            
        # 10. prepayment (uint64)
        if prepayment > 0:
            msg.extend(self._uint64_to_bytes(prepayment))
            
        # 11. key & val (string)
        # Key and Val are strings in protobuf, server appends raw bytes directly
        if key:
            msg.extend(key.encode('utf-8'))
            if val:
                msg.extend(val.encode('utf-8'))
        
        # Calculate Keccak256 hash
        k = keccak.new(digest_bits=256)
        k.update(msg)
        return k.digest()

    def send_transaction(self, private_key_hex, to_hex, amount=0, 
                         nonce=1, gas_limit=50000, gas_price=1, 
                         step=0, shard_id=0,
                         contract_code='', input_hex='', prepayment=0,
                         key='', val=''):
        
        # 1. Handle Private and Public Keys
        if private_key_hex.startswith('0x'):
            private_key_hex = private_key_hex[2:]
        
        priv_key = PrivateKey.from_hex(private_key_hex)
        
        # Get uncompressed public key (65 bytes: 04 + X + Y)
        pubkey_bytes = priv_key.public_key.format(compressed=False)
        pubkey_hex = pubkey_bytes.hex()
        
        # Note: Depending on your C++ logic, adjust based on server address generation rules
        # If server uses standard 65-byte pubkey, keep '04' prefix.
        # If server expects 64 bytes (removing '04'), uncomment below:
        # if pubkey_hex.startswith('04'):
        #     pubkey_hex = pubkey_hex[2:]

        # 2. Compute Hash Locally
        tx_hash = self.compute_hash(
            nonce, pubkey_hex, to_hex, amount, gas_limit, gas_price, step,
            contract_code, input_hex, prepayment, key, val
        )
        print(f"[Client] Computed Hash: {tx_hash.hex()}")

        # 3. Sign (ECDSA Recoverable)
        # hasher=None means the input message is already a hash, do not hash again
        signature = priv_key.sign_recoverable(tx_hash, hasher=None)
        
        # coincurve returns signature in 65 bytes (R + S + V)
        # R = 32 bytes, S = 32 bytes, V = 1 byte
        r_bytes = signature[0:32]
        s_bytes = signature[32:64]
        v_byte = signature[64] # 0 or 1

        # 4. Construct Request Parameters
        data = {
            "nonce": str(nonce),
            "pubkey": pubkey_hex,
            "to": to_hex,
            "amount": str(amount),
            "gas_limit": str(gas_limit),
            "gas_price": str(gas_price),
            "shard_id": str(shard_id),
            "type": str(step),
            "sign_r": r_bytes.hex(),
            "sign_s": s_bytes.hex(),
            "sign_v": str(v_byte) # Server expects integer as string
        }

        # Add optional parameters
        if contract_code: data["bytes_code"] = contract_code
        if input_hex: data["input"] = input_hex
        if prepayment > 0: data["pepay"] = str(prepayment)
        if key: data["key"] = key
        if val: data["val"] = val

        print("[Client] Sending Request:", data)

        try:
            resp = requests.post(self.url, data=data, timeout=5)
            print(f"[Server Response] Status: {resp.status_code}, Body: {resp.text}")
            return resp.status_code == 200 and "ok" in resp.text
        except Exception as e:
            print(f"[Error] Request failed: {e}")
            return False

# ==========================================
# Usage Example
# ==========================================
if __name__ == "__main__":
    # Configuration
    HOST = "127.0.0.1"
    PORT = 8888
    
    # Test Account Info
    PRIVATE_KEY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    TO_ADDR = "1234567890abcdef1234567890abcdef12345678" # Target Address (no 0x, 40 chars)
    
    client = SethClient(HOST, PORT)
    
    # Send Transaction
    client.send_transaction(
        private_key_hex=PRIVATE_KEY,
        to_hex=TO_ADDR,
        amount=1000,
        nonce=1,
        gas_limit=50000,
        gas_price=1,
        input_hex="aabbcc" # Optional: Contract call data
    )