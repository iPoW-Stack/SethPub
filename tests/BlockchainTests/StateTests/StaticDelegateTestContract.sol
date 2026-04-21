// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Helper {
    uint256 public val;

    function setVal(uint256 v) external {
        val = v;
    }

    function getVal() external view returns (uint256) {
        return val;
    }

    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }

    function revertMe() external pure {
        revert("helper revert");
    }
}

contract StaticDelegateTest {
    uint256 public val;
    address public helper;

    constructor(address _helper) {
        helper = _helper;
    }

    // STATICCALL: call view function
    function staticAdd(uint256 a, uint256 b) external view returns (bool ok, uint256 result) {
        bytes memory data = abi.encodeWithSignature("add(uint256,uint256)", a, b);
        bytes memory ret;
        (ok, ret) = helper.staticcall(data);
        if (ok && ret.length >= 32) {
            result = abi.decode(ret, (uint256));
        }
    }

    // STATICCALL: call getVal (view)
    function staticGetVal() external view returns (bool ok, uint256 result) {
        bytes memory data = abi.encodeWithSignature("getVal()");
        bytes memory ret;
        (ok, ret) = helper.staticcall(data);
        if (ok && ret.length >= 32) {
            result = abi.decode(ret, (uint256));
        }
    }

    // STATICCALL: attempt state change should fail
    function staticSetVal(uint256 v) external view returns (bool ok) {
        bytes memory data = abi.encodeWithSignature("setVal(uint256)", v);
        (ok, ) = helper.staticcall(data);
    }

    // STATICCALL: revert propagation
    function staticRevert() external view returns (bool ok) {
        bytes memory data = abi.encodeWithSignature("revertMe()");
        (ok, ) = helper.staticcall(data);
    }

    // DELEGATECALL: setVal changes THIS contract's storage
    function delegateSetVal(uint256 v) external returns (bool ok) {
        bytes memory data = abi.encodeWithSignature("setVal(uint256)", v);
        (ok, ) = helper.delegatecall(data);
    }

    // DELEGATECALL: getVal reads THIS contract's storage
    function delegateGetVal() external returns (bool ok, uint256 result) {
        bytes memory data = abi.encodeWithSignature("getVal()");
        bytes memory ret;
        (ok, ret) = helper.delegatecall(data);
        if (ok && ret.length >= 32) {
            result = abi.decode(ret, (uint256));
        }
    }

    // DELEGATECALL: pure function
    function delegateAdd(uint256 a, uint256 b) external returns (bool ok, uint256 result) {
        bytes memory data = abi.encodeWithSignature("add(uint256,uint256)", a, b);
        bytes memory ret;
        (ok, ret) = helper.delegatecall(data);
        if (ok && ret.length >= 32) {
            result = abi.decode(ret, (uint256));
        }
    }

    // DELEGATECALL: revert propagation
    function delegateRevert() external returns (bool ok) {
        bytes memory data = abi.encodeWithSignature("revertMe()");
        (ok, ) = helper.delegatecall(data);
    }

    // Direct read of val
    function readVal() external view returns (uint256) {
        return val;
    }
}
