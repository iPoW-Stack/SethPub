// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ZeroBoundaryTest {
    uint256 public val;

    receive() external payable {}

    // Zero-value CALL to contract
    function zeroCallTo(address target) external returns (bool ok) {
        (ok, ) = target.call{value: 0}("");
    }

    // Zero-value CALL with data
    function zeroCallWithData(address target, bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = target.call{value: 0}(data);
    }

    // Zero-value DELEGATECALL
    function zeroDelegatecall(address target) external returns (bool ok) {
        (ok, ) = target.delegatecall(abi.encodeWithSignature("getVal()"));
    }

    // Zero-value STATICCALL
    function zeroStaticcall(address target) external view returns (bool ok, uint256 result) {
        (bool s, bytes memory ret) = target.staticcall(abi.encodeWithSignature("getVal()"));
        ok = s;
        if (s && ret.length >= 32) result = abi.decode(ret, (uint256));
    }

    // Call to zero address (0x0)
    function callZeroAddr() external returns (bool ok) {
        (ok, ) = address(0).call{value: 0}("");
    }

    // Call to non-existent contract (random addr)
    function callNonExistent(address target) external returns (bool ok) {
        (ok, ) = target.call{value: 0}(abi.encodeWithSignature("foo()"));
    }

    // Zero-value call + revert
    function zeroCallRevert(address target) external returns (bool ok) {
        (ok, ) = target.call{value: 0}(abi.encodeWithSignature("doRevert()"));
    }

    // Set and read val (for delegatecall target)
    function setVal(uint256 v) external { val = v; }
    function getVal() external view returns (uint256) { return val; }

    // Revert function
    function doRevert() external pure { revert("zero revert"); }

    // SELFBALANCE
    function getSelfBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // Balance of arbitrary address
    function getBalance(address a) external view returns (uint256) {
        return a.balance;
    }

    // Non-zero value call (transfer)
    function nonZeroCall(address payable target) external payable returns (bool ok) {
        (ok, ) = target.call{value: msg.value}("");
    }
}
