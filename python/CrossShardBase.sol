// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * CrossShardBase — 跨分片资产协议基类
 *
 * 用法：
 *   contract MyToken is CrossShardBase {
 *       constructor(address systemExecutor, address baseRootAddress)
 *           CrossShardBase(systemExecutor, baseRootAddress) {}
 *
 *       function _baseInit() internal override {
 *           _balances[tx.origin] = 1_000_000 ether;
 *           totalSupply = 1_000_000 ether;
 *       }
 *   }
 *
 * 分身合约由共识层直接写 runtime bytecode + 存储槽部署，构造函数不运行，
 * 因此 _baseInit() 永远不会在分身分片上执行。
 */
abstract contract CrossShardBase {

    // ─────────────────────────────────────────────────────────────────────
    // 固定存储槽（C++ 侧通过相同常量值定位）
    // keccak256("seth.cross_shard_base.marker.v1")
    // ─────────────────────────────────────────────────────────────────────
    bytes32 private constant IS_CROSS_SHARD_BASE_SLOT =
        0xc1f51986c7b4d6e0c3e3a3f5a6b7d8e9f0a1b2c3d4e5f6789abcdef01234567;

    // ─────────────────────────────────────────────────────────────────────
    // 共识层固定 SYSTEM_EXECUTOR 地址（= ASCII "SYSTEM_EXECUTOR_V1" + 0x0000）
    // 部署 CrossShardBase 时 systemExecutor 参数必须等于此值
    // ─────────────────────────────────────────────────────────────────────
    address public constant SYSTEM_EXECUTOR_ADDRESS =
        0x53595354454d5f4558454355544f525f56310000;

    // ─────────────────────────────────────────────────────────────────────
    // Feistel 参数
    // ─────────────────────────────────────────────────────────────────────
    bytes private constant DOMAIN_TAG = "AKAVERSE_FEISTEL_V1";
    uint256 private constant MASK_80  = (1 << 80) - 1;

    // ─────────────────────────────────────────────────────────────────────
    // 状态
    // ─────────────────────────────────────────────────────────────────────
    bool    public IS_ROOT;
    address public BASE_ROOT_ADDRESS;
    address public SYSTEM_EXECUTOR;

    mapping(address => uint256) internal _balances;
    uint256 public totalSupply;

    // ─────────────────────────────────────────────────────────────────────
    // 事件
    // ─────────────────────────────────────────────────────────────────────
    event CrossTransferOut(
        address indexed base,
        address indexed from,
        address         to,
        uint256         amount,
        uint64          nonce,
        uint32          toShard,
        uint32          toPool
    );
    event CrossTransferIn(
        address indexed base,
        address         to,
        uint256         amount,
        uint64          nonce
    );
    event CrossStorageOut(
        address indexed base,
        bytes32 indexed key,
        bytes           value,
        uint64          nonce,
        uint32          toShard,
        uint32          toPool
    );
    event CrossStorageIn(
        address indexed base,
        bytes32         key,
        bytes           value,
        uint64          version
    );

    // ─────────────────────────────────────────────────────────────────────
    // 修饰符
    // ─────────────────────────────────────────────────────────────────────
    modifier onlySystemExecutor() {
        require(msg.sender == SYSTEM_EXECUTOR, "ONLY_SYSTEM_EXECUTOR");
        _;
    }

    /// 仅限 base 分片（IS_ROOT == true）调用
    modifier onlyBase() {
        require(IS_ROOT, "ONLY_BASE_SHARD");
        _;
    }

    // ─────────────────────────────────────────────────────────────────────
    // 构造函数（只在 base 合约部署时运行，分身由共识层直接写状态）
    // ─────────────────────────────────────────────────────────────────────
    constructor(
        address systemExecutor,
        address baseRootAddress
    ) {
        require(systemExecutor  != address(0), "ZERO_SYSTEM_EXECUTOR");
        require(baseRootAddress != address(0), "ZERO_BASE_ROOT");
        require(address(this) == baseRootAddress, "BASE_ADDR_MISMATCH");

        SYSTEM_EXECUTOR   = systemExecutor;
        BASE_ROOT_ADDRESS = baseRootAddress;
        IS_ROOT           = true;

        _baseInit();

        // 写系统标记槽，供 C++ block_acceptor.cc 检测
        assembly {
            sstore(IS_CROSS_SHARD_BASE_SLOT, 1)
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 用户钩子：仅在 base 分片初始化（mint、设置 owner 等）
    // 分身合约永远不调用此函数
    // ─────────────────────────────────────────────────────────────────────
    function _baseInit() internal virtual {}

    // ─────────────────────────────────────────────────────────────────────
    // 跨链转账（任意分片均可发起，不限 base）
    // ─────────────────────────────────────────────────────────────────────
    function _crossTransfer(
        address to,
        uint256 amount,
        uint32  toShard,
        uint32  toPool
    ) internal returns (uint64 nonce) {
        require(to != address(0),             "ZERO_TO");
        require(_balances[msg.sender] >= amount, "INSUFFICIENT_BALANCE");

        _balances[msg.sender] -= amount;
        totalSupply            -= amount;

        // nonce 由共识层在 emit_log 拦截时分配，此处占位 0
        nonce = 0;
        emit CrossTransferOut(BASE_ROOT_ADDRESS, msg.sender, to, amount, nonce, toShard, toPool);
    }

    // ─────────────────────────────────────────────────────────────────────
    // 系统入口：目标分片共识层调用，完成资产到账
    // ─────────────────────────────────────────────────────────────────────
    function systemExecuteCrossTransfer(
        address to,
        uint256 amount,
        uint64  nonce
    ) external onlySystemExecutor {
        require(to != address(0), "ZERO_TO");

        _balances[to] += amount;
        totalSupply   += amount;

        emit CrossTransferIn(BASE_ROOT_ADDRESS, to, amount, nonce);
    }

    // ─────────────────────────────────────────────────────────────────────
    // 跨链存储写入（任意分片均可发起）
    // ─────────────────────────────────────────────────────────────────────
    function _crossSetStorage(
        bytes32     key,
        bytes memory value,
        uint32      toShard,
        uint32      toPool
    ) internal returns (uint64 nonce) {
        nonce = 0;  // 共识层拦截时填入真实 nonce
        emit CrossStorageOut(BASE_ROOT_ADDRESS, key, value, nonce, toShard, toPool);
    }

    // 系统入口：目标分片共识层调用，同步存储写入
    function systemExecuteCrossStorage(
        bytes32        key,
        bytes calldata value,
        uint64         version
    ) external onlySystemExecutor {
        _crossStorageSet(key, value);
        emit CrossStorageIn(BASE_ROOT_ADDRESS, key, value, version);
    }

    // 用户可覆盖：定义 key → storage 的实际写入逻辑
    function _crossStorageSet(bytes32 key, bytes calldata value) internal virtual {}

    // ─────────────────────────────────────────────────────────────────────
    // Feistel 地址派生（4 轮，80-bit L/R 半块）
    // ─────────────────────────────────────────────────────────────────────
    function _feistelRoundKey(
        uint32  shard,
        uint32  pool,
        uint256 round
    ) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(DOMAIN_TAG, shard, pool, round))) & MASK_80;
    }

    function deriveShardAddress(
        address base,
        uint32  shard,
        uint32  pool
    ) internal pure returns (address) {
        uint256 v   = uint256(uint160(base));
        uint256 L   = v >> 80;
        uint256 R   = v & MASK_80;

        for (uint256 i = 0; i < 4; i++) {
            uint256 rk  = _feistelRoundKey(shard, pool, i);
            uint256 tmp = R;
            R = L ^ (keccak256Compress(R ^ rk) & MASK_80);
            L = tmp;
        }
        return address(uint160((L << 80) | R));
    }

    function recoverBaseAddress(
        address derived,
        uint32  shard,
        uint32  pool
    ) internal pure returns (address) {
        uint256 v = uint256(uint160(derived));
        uint256 L = v >> 80;
        uint256 R = v & MASK_80;

        // 逆序轮密钥
        for (uint256 i = 4; i > 0; i--) {
            uint256 rk  = _feistelRoundKey(shard, pool, i - 1);
            uint256 tmp = L;
            L = R ^ (keccak256Compress(L ^ rk) & MASK_80);
            R = tmp;
        }
        return address(uint160((L << 80) | R));
    }

    // keccak256 压缩到 80 bit（复用 solidity 内置，截断高位）
    function keccak256Compress(uint256 x) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(x)));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 查询
    // ─────────────────────────────────────────────────────────────────────
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
