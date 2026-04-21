// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MemoryStackTest {
    // MEMORY: mstore/mload round-trip
    function memStoreLoad(uint256 v) external pure returns (uint256 result) {
        assembly {
            mstore(0x80, v)
            result := mload(0x80)
        }
    }

    // MEMORY: mstore8 stores single byte
    function memStore8(uint8 v) external pure returns (uint8 result) {
        assembly {
            mstore8(0x80, v)
            result := byte(0, mload(0x80))
        }
    }

    // MEMORY: msize grows with access
    function memSize() external pure returns (uint256 s2) {
        assembly {
            mstore(0x100, 1)
            s2 := mload(0x100)
        }
    }

    // MEMORY: calldatacopy
    function calldataCopyTest(uint256 v) external pure returns (uint256 result) {
        assembly {
            calldatacopy(0x80, 4, 32)
            result := mload(0x80)
        }
    }

    // MEMORY: large allocation
    function memLargeAlloc() external pure returns (uint256 val) {
        assembly {
            mstore(0x1000, 42)
            val := mload(0x1000)
        }
    }

    // MEMORY: keccak256 of memory region
    function memKeccak(uint256 v) external pure returns (bytes32 h) {
        assembly {
            mstore(0x80, v)
            h := keccak256(0x80, 32)
        }
    }

    // STACK: dup and swap via computation
    function stackDupSwap(uint256 a, uint256 b) external pure returns (uint256 sum, uint256 diff) {
        sum = a + b;
        diff = a - b;
    }

    // STACK: deep computation (tests stack depth)
    function stackDeep(uint256 x) external pure returns (uint256) {
        uint256 a = x + 1;
        uint256 b = a + 2;
        uint256 c = b + 3;
        uint256 d = c + 4;
        uint256 e = d + 5;
        uint256 f = e + 6;
        uint256 g = f + 7;
        uint256 h = g + 8;
        return h;
    }

    // STACK: multiple returns
    function stackMultiReturn(uint256 x) external pure returns (uint256, uint256, uint256) {
        return (x, x * 2, x * 3);
    }

    // RETURNDATA: return dynamic bytes
    function returnDynamic(uint256 n) external pure returns (bytes memory) {
        bytes memory data = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            data[i] = bytes1(uint8(i & 0xff));
        }
        return data;
    }

    // RETURNDATA: return empty
    function returnEmpty() external pure returns (bytes memory) {
        return "";
    }

    // RETURNDATASIZE via external call
    function getReturnDataSize(address target) external view returns (uint256 rdSize) {
        bytes memory data = abi.encodeWithSignature("memSize()");
        assembly {
            let ok := staticcall(gas(), target, add(data, 0x20), mload(data), 0, 0)
            rdSize := returndatasize()
        }
    }
}
