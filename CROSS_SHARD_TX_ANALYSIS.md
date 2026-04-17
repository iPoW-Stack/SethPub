# Seth Cross-Shard Transaction Analysis

## Overview

This document analyzes the cross-shard transaction mechanism in Seth, covering `block_manager`, `to_txs_pools`, `root_cross_pool`, `cross_pool`, and `cross_block_manager`.

---

## 1. Architecture

### 1.1 Two Routing Paths

Seth uses **adaptive routing**: if the source shard knows the destination address's shard, it routes directly; otherwise it falls back to the root shard for address resolution.

```
                    ┌─────────────────────────────┐
                    │  Source Shard Consensus      │
                    │  cross_to_map_ → block      │
                    │  cross_shard_to_array        │
                    └──────────┬──────────────────┘
                               │
                    ToTxsPools.CreateToTxWithHeights()
                               │
                    ┌──────────▼──────────────────┐
                    │  des_sharding_id known?      │
                    │  (acc_mgr_->GetAccountInfo)  │
                    └──────┬──────────┬───────────┘
                           │          │
                      YES  │          │  NO
                           │          │
              ┌────────────▼──┐  ┌────▼────────────┐
              │ Direct Route  │  │ Root Relay       │
              │ to Shard B    │  │ kRootCongress    │
              │ (fast path)   │  │ (address resolve)│
              └────────┬──────┘  └────┬─────────────┘
                       │              │
                       │         RootToTxItem
                       │         assigns shard_id
                       │         dispatches to Shard B
                       │              │
              ┌────────▼──────────────▼──────────────┐
              │         Shard B (Destination)          │
              │  HandleRootCrossShardTx()              │
              │  CreateLocalToTx()                     │
              │  ToTxLocalItem.HandleTx()              │
              │  → credit balance / create address     │
              └────────────────────────────────────────┘
```

### 1.2 Routing Decision (to_txs_pools.cc:390)

```cpp
auto des_sharding_id = to_iter->second.des_sharding_id();
if (des_sharding_id == network::kUniversalNetworkId) {
    // Unknown destination shard — try local account lookup first
    auto addr_info = acc_mgr_->GetAccountInfo(
        to_iter->second.des().substr(0, kUnicastAddressLength));
    if (addr_info) {
        // FAST PATH: address found locally, route directly to its shard
        des_sharding_id = addr_info->sharding_id();
        to_iter->second.set_des_sharding_id(des_sharding_id);
    } else {
        // SLOW PATH: address unknown, route via root for resolution
        des_sharding_id = network::kRootCongressNetworkId;
    }
}
```

**Key insight**: Most transfers to existing addresses take the fast path (direct shard-to-shard), avoiding the root relay entirely. Only new addresses or addresses not yet synced to the local shard go through root.

---

## 2. Core Modules

### 2.1 ToTxsPools (`to_txs_pools.h/cc`)

**Role**: Aggregates cross-shard transfer outputs and routes them to the correct destination.

**Data Structure**:
```
network_txs_pools_[pool_idx] → map<height, map<dest_addr, ToTxMessageItem>>
```

**Flow**:
1. `NewBlock()` → extracts `cross_shard_to_array` from each consensus block
2. Stores transfers indexed by `(pool_index, height, destination)`
3. `LeaderCreateToHeights()` → leader selects height ranges for batching
4. `CreateToTxWithHeights()` → for each transfer:
   - If `des_sharding_id` is known → route to that shard directly
   - If `des_sharding_id == kUniversalNetworkId` → lookup locally → found? direct route : root relay
   - Aggregate same-destination transfers within height range

**Height Tracking**:
- `pool_consensus_heihgts_[]` — latest consensus height per pool
- `prev_to_heights_` — previous batch boundary (monotonically increasing)
- `leader_to_heights_` — current leader's proposed batch boundary

### 2.2 BlockManager (`block_manager.h/cc`)

**Role**: Routes cross-shard transactions between consensus and pool layers.

| Function | Description |
|----------|-------------|
| `HandleNormalToTx()` | Processes batched cross-shard transfers from `kNormalTo` blocks |
| `HandleRootCrossShardTx()` | Processes root-relayed transfers for local shard |
| `CreateLocalToTx()` | Creates `kConsensusLocalTos` transactions with unique hash |
| `HandleToTxsMessage()` | Aggregates transfers across all shards into `AllToTxMessage` |
| `AddMiningToken()` | Creates cross-shard mining reward transfers |

**Unique Hash**: `keccak256(block_hash + BLS_sign_x + BLS_sign_y + destination)` — globally unique, non-replayable.

### 2.3 CrossPool / RootCrossPool

- `CrossPool` — tracks blocks from other consensus shards (used by root)
- `RootCrossPool` — tracks root shard blocks (used by consensus shards)
- Both use `HeightTreeLevel` for efficient sparse height tracking
- `SyncMissingBlocks()` requests missing blocks from remote shards

### 2.4 CrossBlockManager

- Ticks every 10s to verify cross-shard block availability
- Root: checks all consensus shards
- Consensus shard: checks root only
- Requests missing blocks via `kv_sync_->AddSyncHeight()`

### 2.5 Consensus Layer

**ToTxLocalItem** (destination shard):
- Verifies unique hash hasn't been processed (prevents replay)
- Updates account balances
- Creates `ConsensusToTxs` entries in block

**RootToTxItem** (root shard):
- Assigns sharding IDs to new addresses: `(g2(height ^ vss_random) % shards) + base`
- Dispatches transfers to destination shards via `cross_to_map_`
- Preserves library bytes for contract deployment across shards

### 2.6 Transaction Type Routing

| Source Transaction | des_sharding_id | Route |
|-------------------|-----------------|-------|
| `kNormalFrom` (transfer) | `kUniversalNetworkId` → lookup | Direct if found, else Root |
| `kContractCreate` | `kRootCongressNetworkId` (always) | Root (needs address registration) |
| `kCreateLibrary` | `kRootCongressNetworkId` (always) | Root (needs global deployment) |
| `kContractExcute` (value transfer) | `kUniversalNetworkId` → lookup | Direct if found, else Root |
| `kContractGasPrefund` | `kUniversalNetworkId` → lookup | Direct if found, else Root |
| `kContractRefund` | `kUniversalNetworkId` → lookup | Direct if found, else Root |
| Mining rewards | Known shard | Direct |

---

## 3. Security Analysis

### 3.1 Replay Protection (Triple Layer)

| Layer | Mechanism | Location |
|-------|-----------|----------|
| 1 | Unique hash per transfer | `keccak256(block_hash + BLS_sign + dest)` |
| 2 | KV existence check | `GetKeyValue(to, unique_hash)` before processing |
| 3 | Height monotonicity | `prev_heights[i] <= leader_heights[i]` enforced |

### 3.2 Double-Spend Prevention

- Source shard deducts balance atomically during consensus
- Transfer included in `cross_shard_to_array` only after successful consensus
- Destination shard credits only after unique hash verification

### 3.3 Address Assignment Security

New addresses assigned deterministically by root:
```cpp
shard_id = (g2(height ^ vss_random) % shard_count) + kConsensusShardBeginNetworkId
```
- VRF-derived randomness — unpredictable before block creation
- Deterministic — all nodes agree on same assignment

### 3.4 Block Integrity

Cross-shard blocks verified via BLS aggregate signatures. The `cross_shard_to_array` is part of the signed block — tampering is detectable.

---

## 4. Performance Analysis

### 4.1 Routing Efficiency

| Scenario | Path | Latency |
|----------|------|---------|
| Known address (common case) | Source → Destination (direct) | 2-6s |
| New address | Source → Root → Destination | 4-12s |
| Contract creation | Source → Root → Destination | 4-12s |

**Optimization**: The `acc_mgr_->GetAccountInfo()` lookup at routing time means most transfers to existing addresses bypass root entirely. This is the dominant case in steady-state operation.

### 4.2 Batching

- Transfers aggregated by destination address within height ranges
- Same-destination amounts merged: `amount += to_iter->second.amount()`
- Max 64 blocks processed per consensus cycle

### 4.3 Latency Breakdown

```
Source consensus:        1-3s
ToTxsPools batching:     ~0s (same block)
Routing decision:        ~0s (local lookup)
─── Direct Path ───
Destination sync:        0-10s (tick interval)
Destination consensus:   1-3s
Total (direct):          2-16s (typical 3-6s)

─── Root Path ───
Root relay consensus:    1-3s
Root address assignment: ~0s
Destination sync:        0-10s
Destination consensus:   1-3s
Total (root):            3-19s (typical 5-10s)
```

### 4.4 Sync Overhead

| Component | Frequency | Cost |
|-----------|-----------|------|
| `CrossBlockManager.Ticking()` | Every 10s | O(shards × pools) |
| `HeightTreeLevel` | Per update | O(1) amortized |
| Missing block sync | Per tick | O(missing_heights) |

---

## 5. Known Limitations & Recommendations

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| In-transit fund risk | Fund loss on permanent partition | Add timeout-based refund or receipt confirmation |
| 10s sync tick interval | Delays cross-shard processing | Reduce to 3s or event-driven sync |
| Contract creation always via root | Higher latency for deploys | Could pre-assign shard for known deployer |
| SpinMutex on `network_txs_pools_` | CPU waste under contention | Replace with std::mutex |
| No cross-shard receipt | Cannot verify delivery | Add receipt confirmation protocol |
| `acc_mgr_` lookup miss for new addresses | Falls back to root | Cache recently resolved addresses |
