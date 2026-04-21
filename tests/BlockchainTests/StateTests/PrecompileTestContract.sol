// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrecompileTestContract {
    // 0x01: ecrecover(hash, v, r, s) -> address
    function testEcrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        external pure returns (address)
    {
        return ecrecover(hash, v, r, s);
    }

    // 0x02: sha256(data) -> bytes32
    function testSha256(bytes memory data) external pure returns (bytes32) {
        return sha256(data);
    }

    // 0x03: ripemd160(data) -> bytes20
    function testRipemd160(bytes memory data) external pure returns (bytes20) {
        return ripemd160(data);
    }

    // 0x04: identity (datacopy) — via assembly
    function testIdentity(bytes memory data) external view returns (bytes memory) {
        bytes memory result = new bytes(data.length);
        assembly {
            let success := staticcall(gas(), 0x04, add(data, 0x20), mload(data), add(result, 0x20), mload(data))
            if iszero(success) { revert(0, 0) }
        }
        return result;
    }

    // 0x05: modexp(base, exp, mod) — EIP-198
    function testModexp(bytes memory base, bytes memory exp, bytes memory mod)
        external view returns (bytes memory)
    {
        uint256 bLen = base.length;
        uint256 eLen = exp.length;
        uint256 mLen = mod.length;
        bytes memory input = abi.encodePacked(
            bytes32(bLen), bytes32(eLen), bytes32(mLen), base, exp, mod
        );
        bytes memory result = new bytes(mLen);
        assembly {
            let success := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(result, 0x20), mLen)
            if iszero(success) { revert(0, 0) }
        }
        return result;
    }
}
