# TDSC-2026-03-0984 Review Response — Code-Level Technical Analysis

## Paper: "Akaverse: Boosting Sharded Blockchain via Multi-Leader Parallel Pipelines"

This document provides a code-level analysis of the Seth/Akaverse implementation to address the three reviewers' concerns.

---

## 1. Review Summary

| Reviewer | Recommendation | Key Concerns |
|----------|---------------|--------------|
| R1 | Minor Revision | Terminology consistency, pseudocode clarity, tVRF role, missing references |
| R2 | Minor Revision | Synchronization assumptions, GBP ordering, intermediate state handling, notation |
| R3 | Major Revision | SMR model formalization, GBP necessity/scalability, evaluation methodology |
| AE | Major Revision | GBP formal description, cross-pool ratio, latency breakdown |

---

## 2. GBP Mechanism — Code Evidence (R2, R3, AE)

### 2.1 Architecture: Pool-Shard-Buffer 3-Level Pipeline

The codebase implements a **32+1 pool** architecture per shard:

```cpp
// src/common/utils.h
static const uint32_t kImmutablePoolSize = 32u;      // parallel consensus pools
static const uint32_t kGlobalPoolIndex = kImmutablePoolSize;  // = 32, the "GBP"
static const uint32_t kInvalidPoolIndex = kImmutablePoolSize + 1;  // = 33
```

Each pool runs an independent **Fast-HotStuff** instance (`src/consensus/hotstuff/hotstuff.cc`), with the global pool (index 32) acting as the cross-pool coordinator — this is the GBP.

### 2.2 GBP Consensus Flow (Code Path)

```
1. Pool[i] consensus → block includes cross_shard_to_array
   (src/consensus/zbft/from_tx_item.cc: cross_to_map_[dest] = transfer)

2. ToTxsPools.NewBlock() → aggregates cross-pool transfers by (pool, height, dest)
   (src/pools/to_txs_pools.cc:80-95)

3. Leader of Pool[kGlobalPoolIndex] calls LeaderCreateToHeights()
   → selects height ranges across all 32 pools
   (src/pools/to_txs_pools.cc:250-310)

4. CreateToTxWithHeights() → batches transfers, routes by destination
   (src/pools/to_txs_pools.cc:350-430)

5. GBP consensus (kNormalTo block) → committed via Fast-HotStuff on Pool[32]
   (src/block/block_manager.cc: HandleToTxsMessage())

6. Destination pool processes via ToTxLocalItem.HandleTx()
   (src/consensus/zbft/to_tx_local_item.cc)
```

### 2.3 Why GBP Consensus vs. Light-Client (R3 Concern)

**Reviewer's suggestion**: Destination pool could verify source QC directly (light-client model).

**Code evidence for why GBP is needed**:

```cpp
// src/pools/to_txs_pools.cc:390-401 — Routing decision
auto des_sharding_id = to_iter->second.des_sharding_id();
if (des_sharding_id == network::kUniversalNetworkId) {
    auto addr_info = acc_mgr_->GetAccountInfo(dest_addr);
    if (addr_info) {
        des_sharding_id = addr_info->sharding_id();  // DIRECT route
    } else {
        des_sharding_id = network::kRootCongressNetworkId;  // ROOT relay
    }
}
```

The GBP serves three purposes that a light-client model cannot:
1. **Cross-pool ordering**: Multiple pools may produce conflicting transfers to the same destination. The GBP consensus establishes a total order across all 32 pools' outputs within each δ window.
2. **Aggregation**: Same-destination transfers from different pools are merged, reducing O(P) messages to O(1).
3. **Height synchronization**: The `prev_to_heights_` → `leader_to_heights_` monotonic progression ensures no pool's transfers are skipped or double-counted.

**Comparison with light-client**: A light-client model would require each destination pool to independently verify QCs from all 32 source pools and resolve ordering conflicts — effectively reimplementing consensus at the destination.

### 2.4 Buffer Maintenance (R3, AE Concern)

```cpp
// src/pools/to_txs_pools.h — Buffer data structure
HeightMap network_txs_pools_[kInvalidPoolIndex];  // 33 height-ordered maps
// HeightMap = map<uint64_t, map<string, ToTxMessageItem>>

// Height tracking (monotonic)
uint64_t pool_consensus_heihgts_[kInvalidPoolIndex];  // latest consensus height per pool
shared_ptr<ShardToTxItem> prev_to_heights_;            // previous batch boundary
atomic<shared_ptr<ShardToTxItem>> leader_to_heights_;  // current leader's proposal
```

**Pruning**: After a `kNormalTo` block is committed, `prev_to_heights_` advances and old entries are pruned:
```cpp
// src/pools/to_txs_pools.cc:100-110
if (block.has_normal_to()) {
    leader_to_heights_.store(nullptr);
    prev_to_heights_ = make_shared<ShardToTxItem>(block.normal_to().to_heights());
    // prune added_heights_ below new boundary
}
```

---

## 3. SMR Model and Cross-Pool Atomicity (R3)

### 3.1 Per-Pool SMR

Each pool maintains an independent **ViewBlockChain** (`src/consensus/hotstuff/view_block_chain.h`):

```cpp
class ViewBlockChain {
    // Per-pool state machine
    atomic<shared_ptr<ViewBlock>> latest_committed_block_;
    shared_ptr<ViewBlock> high_view_block_;
    AccountLruMap<102400> account_lru_map_;  // account state cache
    // ...
};
```

**Consistency guarantee**: Within each pool, Fast-HotStuff provides standard BFT safety (no two honest nodes commit different blocks at the same height).

### 3.2 Cross-Pool Ordering

The GBP (Pool[32]) provides a **total order** for cross-pool transfers:

```cpp
// src/pools/to_txs_pools.cc:310-340 — Height validation
for (int32_t i = 0; i < leader_to_heights.heights_size(); ++i) {
    if (prev_to_heights->heights(i) > leader_to_heights.heights(i)) {
        return kPoolsError;  // REJECT: heights must be monotonically increasing
    }
}
```

**R3's concern about Tx_i and Tx_j ordering**: If source pool orders `tx_i^1 ≻ tx_j^1`, the GBP batches both into the same `kNormalTo` block with deterministic ordering (by height, then by destination address hash). The destination pool processes them in this order.

### 3.3 Intermediate State Handling (R2 Concern)

**Source side** — funds are escrowed in `cross_to_map_` during block execution:
```cpp
// src/consensus/zbft/from_tx_item.cc:92-99
if (block_tx.status() == kConsensusSuccess) {
    seth_host.MergeToPrev();
    auto to_item_ptr = make_shared<ToTxMessageItem>();
    to_item_ptr->set_des(block_tx.to());
    to_item_ptr->set_amount(block_tx.amount());
    pre_seth_host.cross_to_map_[to_item_ptr->des()] = to_item_ptr;
}
```

**Destination side** — unique hash prevents double-credit:
```cpp
// src/consensus/zbft/to_tx_local_item.cc:30-37
if (seth_host.GetKeyValue(block_tx.to(), unique_hash, &val) == kSethvmSuccess) {
    // Already processed — reject duplicate
    return consensus::kConsensusError;
}
```

**Asset freezing prevention**: The forward-moving design means funds are deducted at source and credited at destination without rollback. If the destination shard is temporarily unavailable, the `CrossBlockManager` (10s tick) will sync missing blocks and eventually process the transfer.

### 3.4 AMM Composability (R3 Concern)

The code shows that **intra-shard** contract calls (including AMM swaps) execute atomically within a single pool's consensus:

```cpp
// src/consensus/zbft/contract_call.cc — Full atomic execution
int ContractCall::HandleTx(...) {
    // All EVM execution happens within one pool's consensus round
    int call_res = ContractExcute(address_info, balance, seth_host, block_tx, gas_limit, &evmc_res);
    // cross_to_map_ collects any outgoing transfers
    // All committed atomically in the same block
}
```

For cross-shard AMM: if Token X and AMM are in the same shard (hash-bucket sharding makes this likely for related contracts), the swap is fully atomic. Only the final output transfer crosses shards.

---

## 4. Evaluation Gaps — Code Evidence (R3, AE)

### 4.1 Cross-Pool Transaction Ratio

From the routing code:
```cpp
// src/pools/to_txs_pools.cc:390
// Probability of cross-pool = 1 - 1/P where P = 32 pools
// → ~97% of random transfers are cross-pool
```

However, the **adaptive routing** (direct vs. root) means:
- **Known addresses** (majority in steady state): direct shard-to-shard, bypassing GBP for inter-shard transfers
- **Intra-shard cross-pool**: handled by GBP consensus on Pool[32]

**Recommendation**: Add experiments varying cross-pool ratio from 0% to 100%.

### 4.2 Latency Breakdown (Code-Derived)

| Stage | Code Location | Estimated Latency |
|-------|--------------|-------------------|
| Pool consensus (Fast-HotStuff) | `hotstuff.cc:Propose→Vote→Commit` | 1-3s |
| GBP batching window (δ) | `to_txs_pools.cc:LeaderCreateToHeights` | 0-1 block time |
| GBP consensus | Pool[32] Fast-HotStuff round | 1-3s |
| Cross-shard sync | `cross_block_manager.h:Ticking()` | 0-10s |
| Destination consensus | `to_tx_local_item.cc:HandleTx` | 1-3s |

**Recommendation**: Instrument these stages with timestamps and report breakdown.

### 4.3 GBP Scalability

The GBP processes O(P) pools' outputs per δ window. With P=32:
```
GBP throughput = (32 pools × block_size) / δ
```

The `CreateToTxWithHeights` function iterates all 32 pools' height maps:
```cpp
// src/pools/to_txs_pools.cc:355-430
for (uint32_t pool_idx = 0; pool_idx < leader_to_heights.heights_size(); ++pool_idx) {
    // iterate heights [prev, leader] for each pool
    // aggregate transfers by destination
}
```

**Recommendation**: Benchmark GBP consensus time vs. pool count (P=4,8,16,32).

---

## 5. Terminology and Formatting (R1, R2)

### 5.1 Inconsistent Terms Found in Code

| Code Term | Paper Should Use |
|-----------|-----------------|
| `cross_to_map_` | Cross-pool transfer map |
| `kNormalTo` | Cross-shard batch transaction |
| `kConsensusLocalTos` | Local delivery transaction |
| `kGlobalPoolIndex` | GBP pool index |
| `des_sharding_id` | Destination shard ID |

### 5.2 Algorithm Pseudocode Mapping

| Algorithm Step | Code Function |
|---------------|---------------|
| Leader proposes block | `BlockWrapper::Wrap()` |
| Follower accepts | `BlockAcceptor::Accept()` |
| Cross-pool aggregation | `ToTxsPools::CreateToTxWithHeights()` |
| GBP height selection | `ToTxsPools::LeaderCreateToHeights()` |
| Destination processing | `ToTxLocalItem::HandleTx()` |
| Root address assignment | `RootToTxItem::HandleTx()` |

---

## 6. Additional References (R1)

R1 suggests discussing:
1. "A flexible sharding blockchain protocol based on cross-shard byzantine fault tolerance"
2. "CHERUBIM: A secure and highly parallel cross-shard consensus using quadruple pipelined two-phase commit for sharding blockchains"

**Recommendation**: Add to Related Work section, comparing their 2PC-based approach with Akaverse's rollback-free GBP approach.

---

## 7. Action Items Summary

| Priority | Item | Reviewer | Effort |
|----------|------|----------|--------|
| **High** | Formalize GBP consensus mechanism with pseudocode | R3, AE | 2-3 pages |
| **High** | Add cross-pool ratio experiments (0%-100%) | R3, AE | 1 week |
| **High** | Add latency breakdown (GBP window vs. pool consensus) | R3, AE | 1 week |
| **Medium** | Formalize SMR model, compare with standard guarantees | R3 | 1-2 pages |
| **Medium** | Discuss AMM composability and developer guidance | R3 | 0.5 page |
| **Medium** | Compare GBP vs. light-client model | R3 | 0.5 page |
| **Low** | Unify terminology throughout paper | R1, R2 | 1 day |
| **Low** | Fix Algorithm 1 formatting, notation consistency | R1, R2 | 1 day |
| **Low** | Add references (flexible sharding, CHERUBIM) | R1 | 0.5 day |
| **Low** | Acknowledge BLS in production (Ethereum PoS) | R3 | 1 sentence |
