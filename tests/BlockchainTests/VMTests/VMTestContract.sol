// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VMTestContract - Tests basic EVM opcodes on Seth chain
 * @notice Covers arithmetic, bitwise, comparison, flow, memory, storage, log operations
 */
contract VMTestContract {
    uint256 public storedValue;

    // ==================== Arithmetic ====================

    function testAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }

    function testSub(uint256 a, uint256 b) external pure returns (uint256) {
        return a - b;
    }

    function testMul(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }

    function testDiv(uint256 a, uint256 b) external pure returns (uint256) {
        return a / b; // reverts on b=0
    }

    function testMod(uint256 a, uint256 b) external pure returns (uint256) {
        return a % b;
    }

    function testExp(uint256 base, uint256 exponent) external pure returns (uint256) {
        return base ** exponent;
    }

    function testAddMod(uint256 a, uint256 b, uint256 n) external pure returns (uint256) {
        return addmod(a, b, n);
    }

    function testMulMod(uint256 a, uint256 b, uint256 n) external pure returns (uint256) {
        return mulmod(a, b, n);
    }

    // ==================== Bitwise ====================

    function testAnd(uint256 a, uint256 b) external pure returns (uint256) {
        return a & b;
    }

    function testOr(uint256 a, uint256 b) external pure returns (uint256) {
        return a | b;
    }

    function testXor(uint256 a, uint256 b) external pure returns (uint256) {
        return a ^ b;
    }

    function testNot(uint256 a) external pure returns (uint256) {
        return ~a;
    }

    function testShl(uint256 shift, uint256 val) external pure returns (uint256) {
        return val << shift;
    }

    function testShr(uint256 shift, uint256 val) external pure returns (uint256) {
        return val >> shift;
    }

    // ==================== Comparison ====================

    function testLt(uint256 a, uint256 b) external pure returns (bool) {
        return a < b;
    }

    function testGt(uint256 a, uint256 b) external pure returns (bool) {
        return a > b;
    }

    function testEq(uint256 a, uint256 b) external pure returns (bool) {
        return a == b;
    }

    function testIsZero(uint256 a) external pure returns (bool) {
        return a == 0;
    }

    // ==================== Storage ====================

    function testSStore(uint256 val) external {
        storedValue = val;
    }

    function testSLoad() external view returns (uint256) {
        return storedValue;
    }

    // ==================== Memory & Hash ====================

    function testKeccak256(bytes memory data) external pure returns (bytes32) {
        return keccak256(data);
    }

    function testCalldataSize(bytes calldata data) external pure returns (uint256) {
        return data.length;
    }

    // ==================== Environment ====================

    function testAddress() external view returns (address) {
        return address(this);
    }

    function testCaller() external view returns (address) {
        return msg.sender;
    }

    function testCallValue() external payable returns (uint256) {
        return msg.value;
    }

    function testGasLeft() external view returns (uint256) {
        return gasleft();
    }

    // ==================== Log ====================

    event TestLog0(uint256 val);
    event TestLog1(uint256 indexed topic1, uint256 val);
    event TestLog2(uint256 indexed topic1, uint256 indexed topic2, uint256 val);

    function testLog0(uint256 val) external {
        emit TestLog0(val);
    }

    function testLog1(uint256 topic1, uint256 val) external {
        emit TestLog1(topic1, val);
    }

    function testLog2(uint256 topic1, uint256 topic2, uint256 val) external {
        emit TestLog2(topic1, topic2, val);
    }

    // ==================== Revert ====================

    function testRevert(string memory reason) external pure {
        revert(reason);
    }

    function testRequire(bool condition) external pure {
        require(condition, "condition failed");
    }
}
