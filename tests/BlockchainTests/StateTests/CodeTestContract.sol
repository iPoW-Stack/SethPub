// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleTarget {
    uint256 public value = 42;
    function set(uint256 v) external { value = v; }
}

contract CodeTestContract {
    // EXTCODESIZE: get code size of an address
    function getCodeSize(address addr) external view returns (uint256 size) {
        assembly { size := extcodesize(addr) }
    }

    // EXTCODEHASH: get code hash of an address
    function getCodeHash(address addr) external view returns (bytes32 hash) {
        assembly { hash := extcodehash(addr) }
    }

    // CODESIZE: get own code size
    function getOwnCodeSize() external pure returns (uint256 size) {
        assembly { size := codesize() }
    }

    // EXTCODECOPY: copy code of an address
    function getCode(address addr) external view returns (bytes memory) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        bytes memory code = new bytes(size);
        assembly { extcodecopy(addr, add(code, 0x20), 0, size) }
        return code;
    }

    // Test: EOA has no code
    function isContract(address addr) external view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    // Test: EXTCODEHASH of empty account = 0
    function emptyAccountHash(address addr) external view returns (bytes32 hash) {
        assembly { hash := extcodehash(addr) }
    }

    // SELFBALANCE
    function getSelfBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // ADDRESS
    function getAddress() external view returns (address) {
        return address(this);
    }

    // CHAINID
    function getChainId() external view returns (uint256 id) {
        assembly { id := chainid() }
    }
}
