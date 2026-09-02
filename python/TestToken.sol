// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CrossShardBase_patched.sol";

contract TestToken is CrossShardBase {
    constructor(address systemExecutor)
        CrossShardBase(systemExecutor) {}

    // tx.origin/msg.sender may be 0 in Seth constructor, so _baseInit is a no-op.
    // Call mint() explicitly after deployment.
    function _baseInit() internal override {}

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount, uint32 toShard, uint32 toPool)
        external returns (uint64)
    {
        return _crossTransfer(to, amount, toShard, toPool);
    }

    function setStorage(bytes32 key, bytes memory value, uint32 toShard, uint32 toPool)
        external returns (uint64)
    {
        return _crossSetStorage(key, value, toShard, toPool);
    }

    function _crossStorageSet(bytes32 key, bytes calldata value) internal override {
        bytes32 val;
        assembly { val := calldataload(value.offset) }
        assembly { sstore(key, val) }
    }

    function readStorage(bytes32 key) external view returns (bytes32 val) {
        assembly { val := sload(key) }
    }
}
