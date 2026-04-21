// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SystemOpsTestContract {
    address public owner;
    uint256 public value;

    constructor() payable {
        owner = msg.sender;
    }

    // BALANCE: get balance of address
    function getBalance(address addr) external view returns (uint256) {
        return addr.balance;
    }

    // ORIGIN: get tx.origin
    function getOrigin() external view returns (address) {
        return tx.origin;
    }

    // CALLER: get msg.sender
    function getCaller() external view returns (address) {
        return msg.sender;
    }

    // CALLVALUE: get msg.value
    function getCallValue() external payable returns (uint256) {
        return msg.value;
    }

    // GASPRICE
    function getGasPrice() external view returns (uint256) {
        return tx.gasprice;
    }

    // GASLIMIT (block gas limit)
    function getBlockGasLimit() external view returns (uint256) {
        return block.gaslimit;
    }

    // COINBASE
    function getCoinbase() external view returns (address) {
        return block.coinbase;
    }

    // TIMESTAMP
    function getTimestamp() external view returns (uint256) {
        return block.timestamp;
    }

    // NUMBER (block number)
    function getBlockNumber() external view returns (uint256) {
        return block.number;
    }

    // GASLEFT
    function getGasLeft() external view returns (uint256) {
        return gasleft();
    }

    // State change + verify
    function setValue(uint256 v) external {
        value = v;
    }

    // Transfer native token
    function sendEther(address payable to, uint256 amount) external {
        require(address(this).balance >= amount, "insufficient balance");
        to.transfer(amount);
    }

    receive() external payable {}
}
