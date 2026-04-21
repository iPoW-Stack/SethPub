// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LogShiftTestContract {
    // ==================== LOG Tests ====================
    event Log0Event(uint256 val);
    event Log1Event(uint256 indexed a, uint256 val);
    event Log2Event(uint256 indexed a, uint256 indexed b, uint256 val);
    event Log3Event(uint256 indexed a, uint256 indexed b, uint256 indexed c, uint256 val);
    event TransferEvent(address indexed from, address indexed to, uint256 amount);

    function emitLog0(uint256 val) external { emit Log0Event(val); }
    function emitLog1(uint256 a, uint256 val) external { emit Log1Event(a, val); }
    function emitLog2(uint256 a, uint256 b, uint256 val) external { emit Log2Event(a, b, val); }
    function emitLog3(uint256 a, uint256 b, uint256 c, uint256 val) external { emit Log3Event(a, b, c, val); }
    function emitTransfer(address to, uint256 amount) external {
        emit TransferEvent(msg.sender, to, amount);
    }

    // Multiple events in one tx
    function emitMultiple() external {
        emit Log0Event(1);
        emit Log0Event(2);
        emit Log0Event(3);
    }

    // ==================== Shift Tests ====================
    function shl(uint256 shift, uint256 val) external pure returns (uint256) { return val << shift; }
    function shr(uint256 shift, uint256 val) external pure returns (uint256) { return val >> shift; }

    function sar(uint256 shift, int256 val) external pure returns (int256) { return val >> shift; }

    // Shift edge cases
    function shlMax() external pure returns (uint256) { return 1 << 255; }
    function shrMax() external pure returns (uint256) { return type(uint256).max >> 1; }
    function shlZero() external pure returns (uint256) { return 42 << 0; }
    function shrZero() external pure returns (uint256) { return 42 >> 0; }
    function shlOverflow() external pure returns (uint256) {
        uint256 result;
        assembly { result := shl(256, 1) } // EVM level: should be 0
        return result;
    }
}
