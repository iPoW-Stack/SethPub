// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// --- Solidity compiler feature tests ---
contract SolidityTest {
    // Mapping
    mapping(address => uint256) public balances;

    // Struct
    struct Order {
        address buyer;
        uint256 amount;
        bool filled;
    }
    Order[] public orders;

    // Enum
    enum Status { Pending, Active, Closed }
    Status public status;

    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event OrderCreated(uint256 indexed id, address buyer, uint256 amount);

    // Modifier
    modifier onlyPositive(uint256 v) {
        require(v > 0, "must be positive");
        _;
    }

    // Mapping set/get
    function setBalance(address a, uint256 v) external {
        balances[a] = v;
        emit Transfer(address(0), a, v);
    }

    // Struct push + read
    function createOrder(uint256 amount) external onlyPositive(amount) returns (uint256 id) {
        id = orders.length;
        orders.push(Order(msg.sender, amount, false));
        emit OrderCreated(id, msg.sender, amount);
    }

    function getOrder(uint256 id) external view returns (address buyer, uint256 amount, bool filled) {
        Order storage o = orders[id];
        return (o.buyer, o.amount, o.filled);
    }

    function fillOrder(uint256 id) external {
        orders[id].filled = true;
    }

    function orderCount() external view returns (uint256) {
        return orders.length;
    }

    // Enum set/get
    function setStatus(uint8 s) external {
        status = Status(s);
    }

    // Ternary / conditional
    function max(uint256 a, uint256 b) external pure returns (uint256) {
        return a >= b ? a : b;
    }

    // Array operations
    uint256[] public arr;
    function pushArr(uint256 v) external { arr.push(v); }
    function popArr() external { arr.pop(); }
    function arrLength() external view returns (uint256) { return arr.length; }

    // String/bytes
    function concatBytes(bytes calldata a, bytes calldata b) external pure returns (bytes memory) {
        return abi.encodePacked(a, b);
    }

    // Try/catch
    function tryCatchDiv(uint256 a, uint256 b) external pure returns (bool ok, uint256 result) {
        // Use inline assembly to avoid compiler optimization
        // Solidity 0.8+ doesn't allow try/catch on internal calls
        if (b == 0) return (false, 0);
        return (true, a / b);
    }

    // Receive ether
    receive() external payable {}
}

// --- Code size limit test ---
contract CodeSizeLimitTest {
    // Deploy a contract and check its code size
    function getCodeSize(address a) external view returns (uint256 size) {
        assembly { size := extcodesize(a) }
    }

    // EIP-170: max contract size = 24576 bytes
    // This contract itself should be under the limit
    function selfCodeSize() external pure returns (uint256 size) {
        assembly { size := codesize() }
    }

    // Verify code size is within EIP-170 limit
    function isWithinLimit(address a) external view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(a) }
        return size <= 24576;
    }
}
