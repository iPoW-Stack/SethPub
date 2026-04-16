# CheckBlsConsensusInfo 功能增强

## 功能概述

增强 `BlsManager::CheckBlsConsensusInfo()` 方法，验证 Leader 广播的 BLS 共识信息与本地已验证的 DKG 信息是否一致。

## 实现位置

文件: `d:\work\SethPub\src\bls\bls_manager.cc`
函数: `BlsManager::CheckBlsConsensusInfo()` (行 1025-1147)

## 核心验证逻辑

### 1. **前置条件检查** (行 1031-1063)

```cpp
// 验证以下条件：
- finish_networks_map_ 存在该网络的 finish_item
- finish_item->success_verified 为 true（本地已成功验证）
- elect_members_ 存在该网络的选举成员
- members 列表不为空
- Leader 发来的 member 总数与本地一致
- Leader 提供了 common_pubkey
```

### 2. **共同公钥哈希校验** (行 1048-1063)

- 计算 Leader 发来的 common_pubkey 的 Keccak256 哈希值
- 与本地保存的 `finish_item->max_finish_hash` 比对
- 哈希不匹配则返回 `kBlsError`

### 3. **单个成员验证** (行 1065-1140)

对每个成员执行以下检查：

```
IF Leader 该成员的 BLS 公钥为空:
    SKIP (该成员未参与)
ELSE:
    IF 成员不在本地已验证列表:
        WARN 并 SKIP
    ELSE:
        重建 Leader 的 BLS 公钥对象
        比对 finish_item->all_public_keys[i]
        IF 不匹配:
            WARN 并 SKIP
        ELSE:
            比对 finish_item->all_common_public_keys[i]
            IF 不匹配:
                WARN 并 SKIP
            ELSE:
                ++matched_count
```

### 4. **成功标准** (行 1142-1147)

```
required_count = ceil(n * 80 / 100)
IF matched_count >= required_count:
    RETURN kBlsSuccess
ELSE:
    RETURN kBlsError
```

## 关键参数

| 参数 | 含义 | 备注 |
|------|------|------|
| `network_id` | 共识网络 ID | 从 ElectBlock 获取 |
| `n` | 总成员数 | 与 Leader 发送的成员数核对 |
| `matched_count` | 验证通过的成员数 | 必须 >= 80% 的 n |
| `required_count` | 所需的通过成员数 | 向上取整(n * 80 / 100) |

## 验证流程图

```
CheckBlsConsensusInfo()
    │
    ├─ 检查 finish_networks_map_ 存在
    ├─ 检查 success_verified == true
    ├─ 检查 elect_members_ 存在
    ├─ 检查 members 不为空
    ├─ 检查成员总数一致
    ├─ 检查 common_pubkey 存在
    ├─ 计算 Leader common_pubkey 的哈希
    ├─ 比对 max_finish_hash
    │
    ├─ FOR EACH member in Leader's bls_pubkey:
    │    ├─ IF bls_pk.x_c0().empty() → SKIP
    │    ├─ IF member NOT in verified[] → WARN & SKIP
    │    ├─ 重建 Leader 的 BLS 公钥
    │    ├─ 比对 all_public_keys[i]
    │    ├─ 比对 all_common_public_keys[i]
    │    └─ IF ALL MATCH → ++matched_count
    │
    └─ IF matched_count >= ceil(n * 0.8):
        RETURN kBlsSuccess
       ELSE:
        RETURN kBlsError
```

## 日志输出

### 警告级别 (WARN)

```
[CheckBLS] net X: finish_networks_map_ not found
[CheckBLS] net X: local not success_verified yet
[CheckBLS] net X: elect_members_ not found
[CheckBLS] net X: members is null
[CheckBLS] net X: leader member count != local
[CheckBLS] net X: leader has no common_pubkey
[CheckBLS] net X: leader cpk_hash != local
[CheckBLS] net X: member Y not in local verified list
[CheckBLS] net X: member Y public key mismatch
[CheckBLS] net X: member Y common public key mismatch
```

### 信息级别 (INFO)

```
[CheckBLS] net X: matched=Y, verified=Z, required=80% of N (M), status=SUCCESS/FAILED
```

## 返回值

| 返回值 | 含义 |
|--------|------|
| `kBlsSuccess` | Leader BLS 信息与本地一致，且通过成员 >= 80% |
| `kBlsError` | Leader BLS 信息与本地不一致，或通过成员 < 80% |

## 使用场景

在 `block_acceptor.cc` 中调用（第 643 行）：

```cpp
if (bls_mgr_->CheckBlsConsensusInfo(elect_statistic.elect_block()) != bls::kBlsSuccess) {
    // 拒绝该区块
}
```

用于验证新的选举区块中的 Leader 提供的 BLS 共识信息是否与本节点的 DKG 验证结果一致。

## 核心设计原理

1. **完整性校验**: 比对所有成员的个人 BLS 公钥和共同公钥
2. **容错设计**: 允许最多 20% 的成员偏差（可能是网络延迟等原因）
3. **严格哈希检查**: 公钥集合的哈希值必须完全一致
4. **详细日志**: 每个不匹配的成员都会被记录，便于调试

## 相关数据结构

### BlsFinishItem 中的关键字段

```cpp
std::map<uint32_t, bool> verified;                    // 每个成员是否已验证
std::vector<libff::alt_bn128_G2> all_public_keys;     // 所有成员的 BLS 公钥
std::vector<libff::alt_bn128_G2> all_common_public_keys;  // 所有成员的共同公钥
std::string max_finish_hash;                          // 最多共识的 cpk 哈希
bool success_verified;                                // 是否已成功聚合验证
```

### ElectBlock 中的关键字段

```cpp
prev_members {
    repeated BLSPublicKey bls_pubkey;  // 每个成员的 BLS 公钥
    BLSPublicKey common_pubkey;        // 共同公钥
}
```

## 测试要点

- ✅ common_pubkey 哈希值一致
- ✅ 所有成员公钥一致
- ✅ 成员数 >= 80% 时返回 SUCCESS
- ✅ 成员数 < 80% 时返回 ERROR
- ✅ 空公钥成员被正确跳过
- ✅ 未验证成员被识别并记录
