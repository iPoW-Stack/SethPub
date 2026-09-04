"""
Feistel address derivation matching C++ reversible_feistel_address.h exactly.

Key differences from Solidity (which uses a DIFFERENT preimage layout):
  - C++ tag: first 18 bytes of "AKAVERSE_FEISTEL_V1" = "AKAVERSE_FEISTEL_V"  (no '1')
  - C++ round: uint32 big-endian (4 bytes), not uint256 (32 bytes)
  - C++ preimage: tag(18B) + shard(4B BE) + pool(4B BE) + round(4B BE) = 30 bytes
  - C++ roundKey / F output: keccak256[22:32]  (last 10 bytes of 32-byte hash)
  - C++ F input: XOR R ^ rk as 10-byte arrays, then keccak256 of that 10-byte value
"""

from eth_hash.auto import keccak as _keccak_fn


def _keccak256(data: bytes) -> bytes:
    return bytes(_keccak_fn(data))


# C++ tag is "AKAVERSE_FEISTEL_V1"[:18] == "AKAVERSE_FEISTEL_V"  (note: no trailing '1')
_TAG = b"AKAVERSE_FEISTEL_V1"[:18]


def _feistel_round_key(shard: int, pool: int, round_: int) -> bytes:
    """Returns 10-byte round key: keccak256(tag||shard||pool||round)[22:32]."""
    preimage = (
        _TAG
        + shard.to_bytes(4, "big")
        + pool.to_bytes(4, "big")
        + round_.to_bytes(4, "big")
    )
    h = _keccak256(preimage)
    return h[22:32]  # last 10 bytes


def _feistel_f(R: bytes, rk: bytes) -> bytes:
    """Returns 10-byte F output: keccak256(R ^ rk)[22:32]."""
    assert len(R) == 10 and len(rk) == 10
    xored = bytes(a ^ b for a, b in zip(R, rk))
    h = _keccak256(xored)
    return h[22:32]


def derive_shard_address(base_hex: str, shard: int, pool: int) -> str:
    """
    Forward Feistel: base → derived address for the given shard/pool.
    base_hex: 40-char hex string (no 0x prefix).
    Returns: 40-char hex string (no 0x prefix).
    """
    base_bytes = bytes.fromhex(base_hex.lower().zfill(40))
    L = bytearray(base_bytes[:10])   # high 80 bits
    R = bytearray(base_bytes[10:])   # low  80 bits

    for round_ in range(4):
        rk = _feistel_round_key(shard, pool, round_)
        fout = _feistel_f(bytes(R), rk)
        new_R = bytearray(a ^ b for a, b in zip(L, fout))  # new_R = L ^ F(R, rk)
        L = bytearray(R)   # new_L = old R
        R = new_R

    return (bytes(L) + bytes(R)).hex()


def recover_base_address(derived_hex: str, shard: int, pool: int) -> str:
    """
    Inverse Feistel: derived → base address.
    derived_hex: 40-char hex string (no 0x prefix).
    Returns: 40-char hex string (no 0x prefix).
    """
    derived_bytes = bytes.fromhex(derived_hex.lower().zfill(40))
    L = bytearray(derived_bytes[:10])
    R = bytearray(derived_bytes[10:])

    for round_ in range(3, -1, -1):
        rk = _feistel_round_key(shard, pool, round_)
        fout = _feistel_f(bytes(L), rk)
        new_L = bytearray(a ^ b for a, b in zip(R, fout))  # recovered old_L = R ^ F(L, rk)
        R = bytearray(L)   # recovered old_R = old L
        L = new_L

    return (bytes(L) + bytes(R)).hex()


if __name__ == "__main__":
    # Verification: known values from C++ logs
    # base=dcd78070920fb944b5f2feac18f71406da1a2857  shard=4 pool=22
    # C++ produced: derived=82fd737752f372316593048ee8e2eea7ee379512
    base = "dcd78070920fb944b5f2feac18f71406da1a2857"
    shard, pool = 4, 22
    derived = derive_shard_address(base, shard, pool)
    print(f"base:    {base}")
    print(f"derived: {derived}")
    expected = "82fd737752f372316593048ee8e2eea7ee379512"
    ok = "OK" if derived == expected else f"MISMATCH (expected {expected})"
    print(f"match:   {ok}")

    # Round-trip check
    recovered = recover_base_address(derived, shard, pool)
    rt_ok = "OK" if recovered == base else f"MISMATCH (got {recovered})"
    print(f"round-trip: {rt_ok}")
