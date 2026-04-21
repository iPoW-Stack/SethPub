// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Callee {
    uint256 public value;
    address public lastCaller;

    function setValue(uint256 v) external {
        value = v;
        lastCaller = msg.sender;
    }

    function getValue() external view returns (uint256) {
        return value;
    }

    function getCaller() external view returns (address) {
        return msg.sender;
    }

    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }

    function willRevert() external pure {
        revert("callee revert");
    }

    receive() external payable {}
}

contract CallTestContract {
    Callee public callee;
    uint256 public storedValue;

    constructor(address _callee) {
        callee = Callee(payable(_callee));
    }

    // CALL: normal external call
    function testCall(uint256 v) external returns (bool) {
        callee.setValue(v);
        return true;
    }

    // CALL: read return value
    function testCallReturn(uint256 a, uint256 b) external view returns (uint256) {
        return callee.add(a, b);
    }

    // STATICCALL: read-only call
    function testStaticCall() external view returns (uint256) {
        return callee.getValue();
    }

    // DELEGATECALL: execute callee code in caller's context
    function testDelegateCall(uint256 v) external returns (bool success) {
        (success, ) = address(callee).delegatecall(
            abi.encodeWithSignature("setValue(uint256)", v)
        );
    }

    // Low-level CALL with error handling
    function testCallWithRevert() external returns (bool success, bytes memory data) {
        (success, data) = address(callee).call(
            abi.encodeWithSignature("willRevert()")
        );
    }

    // CALL: verify msg.sender is this contract (not original sender)
    function testCallSender() external returns (address) {
        // When this contract calls callee, msg.sender in callee = address(this)
        callee.setValue(1);
        return callee.lastCaller();
    }

    // Read storedValue (set by delegatecall)
    function getStoredValue() external view returns (uint256) {
        return storedValue;
    }
}
