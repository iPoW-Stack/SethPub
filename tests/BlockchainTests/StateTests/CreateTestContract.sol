// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Child {
    uint256 public val;
    constructor(uint256 v) { val = v; }
    function getVal() external view returns (uint256) { return val; }
}

contract CreateTest {
    event Created(address addr);

    // CREATE via new — returns child address
    function createChild(uint256 v) external returns (address child) {
        Child c = new Child(v);
        child = address(c);
        emit Created(child);
    }

    // CREATE with salt (CREATE2 via new)
    function create2Child(uint256 v, bytes32 salt) external returns (address child) {
        Child c = new Child{salt: salt}(v);
        child = address(c);
        emit Created(child);
    }

    // Nested create: factory creates factory creates child
    function nestedCreate(uint256 v) external returns (address child) {
        Child c = new Child(v);
        child = address(c);
    }

    // CREATE that reverts in constructor
    function createReverting() external returns (bool ok) {
        try new Reverter() {
            ok = true;
        } catch {
            ok = false;
        }
    }

    // Self-destruct test target
    function deploySelfDestruct(address payable recipient) external returns (address target) {
        SelfDestructTarget t = new SelfDestructTarget(recipient);
        target = address(t);
    }

    // Gas refund: SSTORE from non-zero to zero
    uint256 public refundSlot = 1;
    function clearSlot() external {
        refundSlot = 0;
    }

    // Gas refund: SSTORE set then clear in same tx
    uint256 public tempSlot;
    function setThenClear(uint256 v) external {
        tempSlot = v;
        tempSlot = 0;
    }

    // Initcode size test: deploy large contract
    function deployLarge() external returns (address child) {
        LargeContract c = new LargeContract();
        child = address(c);
    }
}

contract Reverter {
    constructor() { revert("always revert"); }
}

contract SelfDestructTarget {
    constructor(address payable recipient) payable {
        selfdestruct(recipient);
    }
}

contract LargeContract {
    // Pad with storage to make bytecode larger
    uint256 public a = 1; uint256 public b = 2; uint256 public c = 3;
    uint256 public d = 4; uint256 public e = 5; uint256 public f = 6;
    uint256 public g = 7; uint256 public h = 8; uint256 public i = 9;
    uint256 public j = 10;
    function sum() external view returns (uint256) {
        return a + b + c + d + e + f + g + h + i + j;
    }
}
