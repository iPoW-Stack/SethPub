// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Victim {
    uint256 public balance_;
    bool private locked;

    receive() external payable {
        balance_ += msg.value;
    }

    function deposit() external payable {
        balance_ += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(!locked, "locked");
        locked = true;
        require(balance_ >= amount, "insufficient");
        balance_ -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        locked = false;
    }

    function getBalance() external view returns (uint256) {
        return balance_;
    }
}

contract AttackBadopTest {
    // INVALID opcode (0xfe) — should revert
    function invalidOpcode() external pure returns (uint256) {
        assembly { invalid() }
    }

    // Stack depth: recursive call until depth limit
    uint256 public depth;
    function recursiveCall(uint256 n) external returns (uint256) {
        depth = n;
        if (n == 0) return n;
        // Self-call to increase depth
        (bool ok, bytes memory ret) = address(this).call(
            abi.encodeWithSignature("recursiveCall(uint256)", n - 1)
        );
        if (ok && ret.length >= 32) {
            return abi.decode(ret, (uint256));
        }
        return n; // depth where it stopped
    }

    // Gas bomb: loop consuming all gas
    function gasBomb() external view returns (uint256 i) {
        // This will run out of gas
        for (i = 0; i < type(uint256).max; i++) {
            if (gasleft() < 1000) break;
        }
    }

    // Reentrancy attempt (call victim.withdraw from receive)
    address public victimAddr;
    uint256 public attackCount;

    function setVictim(address v) external { victimAddr = v; }

    function attack() external {
        attackCount = 0;
        Victim(payable(victimAddr)).withdraw(1);
    }

    receive() external payable {
        attackCount++;
        if (attackCount < 3) {
            // Try reentrant call — should fail due to lock
            try Victim(payable(victimAddr)).withdraw(1) {} catch {}
        }
    }

    // Division by zero — Solidity 0.8+ reverts
    function divByZero(uint256 a) external pure returns (uint256) {
        uint256 b = 0;
        return a / b;
    }

    // Overflow — Solidity 0.8+ reverts
    function overflow() external pure returns (uint256) {
        uint256 x = type(uint256).max;
        return x + 1;
    }

    // Underflow — Solidity 0.8+ reverts
    function underflow() external pure returns (uint256) {
        uint256 x = 0;
        return x - 1;
    }

    // Large return data
    function largeReturn() external pure returns (bytes memory) {
        return new bytes(10000);
    }
}
