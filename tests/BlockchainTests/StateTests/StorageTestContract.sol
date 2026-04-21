// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StorageTestContract {
    uint256 public slot0;
    uint256 public slot1;
    mapping(uint256 => uint256) public map;
    mapping(address => uint256) public balances;
    uint256[] public arr;

    // Basic SSTORE/SLOAD
    function setSlot0(uint256 v) external { slot0 = v; }
    function setSlot1(uint256 v) external { slot1 = v; }

    // Set then read in same tx
    function setAndGet(uint256 v) external returns (uint256) {
        slot0 = v;
        return slot0;
    }

    // Multiple writes in one tx
    function multiWrite(uint256 a, uint256 b) external {
        slot0 = a;
        slot1 = b;
    }

    // Write zero (clear storage — triggers gas refund in EVM)
    function clearSlot0() external { slot0 = 0; }

    // Mapping write/read
    function setMap(uint256 key, uint256 val) external { map[key] = val; }
    function getMap(uint256 key) external view returns (uint256) { return map[key]; }

    // Address mapping
    function setBalance(address who, uint256 val) external { balances[who] = val; }
    function getBalance(address who) external view returns (uint256) { return balances[who]; }

    // Dynamic array
    function pushArr(uint256 v) external { arr.push(v); }
    function getArrLen() external view returns (uint256) { return arr.length; }
    function getArr(uint256 i) external view returns (uint256) { return arr[i]; }

    // Overwrite same slot multiple times in one tx
    function overwriteMany(uint256 v1, uint256 v2, uint256 v3) external {
        slot0 = v1;
        slot0 = v2;
        slot0 = v3; // only v3 should persist
    }

    // Read non-initialized slot (should return 0)
    function readUninitialized() external view returns (uint256) {
        uint256 val;
        assembly { val := sload(999) }
        return val;
    }
}
