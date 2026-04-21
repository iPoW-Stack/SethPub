// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Create2TestContract {
    event Deployed(address addr, uint256 salt);

    // Deploy a minimal contract via CREATE2
    function deploy(uint256 salt) external returns (address) {
        // Minimal contract: PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        // Returns 0x42 when called
        bytes memory bytecode = hex"604260005260206000f3";
        address addr;
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "CREATE2 failed");
        emit Deployed(addr, salt);
        return addr;
    }

    // Predict CREATE2 address
    function predict(uint256 salt) external view returns (address) {
        bytes memory bytecode = hex"604260005260206000f3";
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, keccak256(bytecode)
        ));
        return address(uint160(uint256(hash)));
    }

    // Deploy and call the deployed contract
    function deployAndCall(uint256 salt) external returns (address deployed, uint256 result) {
        deployed = this.deploy(salt);
        (bool ok, bytes memory data) = deployed.staticcall("");
        require(ok, "call failed");
        result = abi.decode(data, (uint256));
    }

    // Test: deploy same salt twice should fail
    function deployTwice(uint256 salt) external returns (address first) {
        first = this.deploy(salt);
        // Second deploy with same salt should revert
        this.deploy(salt); // will revert
    }
}
