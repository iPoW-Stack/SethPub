// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RevertTestContract {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    // Revert with reason string
    function revertWithReason() external pure {
        revert("test revert reason");
    }

    // Revert without reason
    function revertNoReason() external pure {
        revert();
    }

    // Require that fails
    function requireFail() external pure {
        require(false, "require failed");
    }

    // Conditional revert
    function conditionalRevert(bool shouldRevert) external pure returns (uint256) {
        if (shouldRevert) {
            revert("conditional revert");
        }
        return 42;
    }

    // Set value then revert — value should NOT persist
    function setAndRevert(uint256 v) external {
        value = v;
        revert("set then revert");
    }

    // Nested call that reverts — outer should catch
    function tryCallRevert() external returns (bool success, bytes memory data) {
        (success, data) = address(this).call(
            abi.encodeWithSignature("revertWithReason()")
        );
    }

    // Custom error
    error CustomError(uint256 code, string message);

    function revertCustomError() external pure {
        revert CustomError(404, "not found");
    }
}
