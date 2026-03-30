// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Minimal pool for Bridge->Treasury->Pool path diagnostics.
 */
contract ProbePool {
    uint256 public reserveSETH;
    uint256 public reserveUSDC;
    uint256 public totalSells;
    uint256 public lastOut;

    constructor(uint256 _reserveSETH, uint256 _reserveUSDC) {
        reserveSETH = _reserveSETH;
        reserveUSDC = _reserveUSDC;
    }

    function sellSETH(uint256 minOut) external payable returns (uint256 out) {
        require(msg.value > 0, "ProbePool: zero in");
        require(reserveSETH > 0 && reserveUSDC > 0, "ProbePool: empty");
        out = (msg.value * reserveUSDC) / (reserveSETH + msg.value);
        require(out >= minOut, "ProbePool: slippage");
        reserveSETH += msg.value;
        reserveUSDC -= out;
        totalSells += 1;
        lastOut = out;
    }
}

